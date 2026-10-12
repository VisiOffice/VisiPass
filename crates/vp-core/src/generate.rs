//! Password generation from the OS random source. Uniform choices only:
//! rejection sampling, never `random % n`.

use crate::Failure;
use crate::secret::Secret;
use serde::{Deserialize, Serialize};

const WORDLIST: &str = include_str!("../data/eff_large_wordlist.txt");
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/~";
const AMBIGUOUS: &str = "0O1lI|`'\"";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Recipe {
    Random {
        length: usize,
        digits: bool,
        symbols: bool,
        avoid_ambiguous: bool,
    },
    Memorable {
        words: usize,
        separator: String,
        capitalize: bool,
        number: bool,
    },
    Pin {
        length: usize,
    },
}

impl Default for Recipe {
    fn default() -> Self {
        Recipe::Random {
            length: 24,
            digits: true,
            symbols: true,
            avoid_ambiguous: true,
        }
    }
}

fn words() -> Vec<&'static str> {
    WORDLIST
        .lines()
        .filter_map(|l| l.split('\t').nth(1))
        .collect()
}

/// A uniform index below `n`.
fn below(n: usize) -> Result<usize, Failure> {
    let n = u64::try_from(n).map_err(|_| Failure::new("Range too large"))?;
    if n == 0 {
        return Err(Failure::new("Nothing to choose from"));
    }
    let zone = u64::MAX - (u64::MAX % n);
    loop {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).map_err(|_| Failure::new("The OS random source failed"))?;
        let value = u64::from_le_bytes(bytes);
        if value < zone {
            return Ok((value % n) as usize);
        }
    }
}

fn pick(chars: &[char]) -> Result<char, Failure> {
    Ok(chars[below(chars.len())?])
}

/// Entropy in bits, for showing strength next to the result.
pub fn entropy(recipe: &Recipe) -> f64 {
    match recipe {
        Recipe::Random { length, .. } => *length as f64 * (alphabet(recipe).len() as f64).log2(),
        Recipe::Memorable {
            words: n, number, ..
        } => *n as f64 * (words().len() as f64).log2() + if *number { 10f64.log2() } else { 0.0 },
        Recipe::Pin { length } => *length as f64 * 10f64.log2(),
    }
}

fn alphabet(recipe: &Recipe) -> Vec<char> {
    let Recipe::Random {
        digits,
        symbols,
        avoid_ambiguous,
        ..
    } = recipe
    else {
        return Vec::new();
    };
    let mut set = String::from(LOWER);
    set.push_str(UPPER);
    if *digits {
        set.push_str(DIGITS);
    }
    if *symbols {
        set.push_str(SYMBOLS);
    }
    set.chars()
        .filter(|c| !*avoid_ambiguous || !AMBIGUOUS.contains(*c))
        .collect()
}

pub fn generate(recipe: &Recipe) -> Result<Secret, Failure> {
    match recipe {
        Recipe::Random {
            length,
            digits,
            symbols,
            avoid_ambiguous,
        } => {
            if !(8..=128).contains(length) {
                return Err(Failure::new("Length must be between 8 and 128"));
            }
            let all = alphabet(recipe);
            let class = |s: &str| -> Vec<char> {
                s.chars()
                    .filter(|c| !*avoid_ambiguous || !AMBIGUOUS.contains(*c))
                    .collect()
            };
            let mut required = vec![class(LOWER), class(UPPER)];
            if *digits {
                required.push(class(DIGITS));
            }
            if *symbols {
                required.push(class(SYMBOLS));
            }
            // Regenerate until every chosen class appears; keeps the distribution uniform over valid passwords.
            loop {
                let candidate: String =
                    (0..*length).map(|_| pick(&all)).collect::<Result<_, _>>()?;
                if required
                    .iter()
                    .all(|set| candidate.chars().any(|c| set.contains(&c)))
                {
                    return Ok(Secret::new(candidate));
                }
            }
        }
        Recipe::Memorable {
            words: n,
            separator,
            capitalize,
            number,
        } => {
            if !(3..=12).contains(n) {
                return Err(Failure::new("Use between 3 and 12 words"));
            }
            let list = words();
            let mut parts: Vec<String> = Vec::with_capacity(*n);
            for _ in 0..*n {
                let word = list[below(list.len())?];
                parts.push(if *capitalize {
                    let mut c = word.chars();
                    c.next()
                        .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
                        .unwrap_or_default()
                } else {
                    word.to_string()
                });
            }
            if *number {
                let at = below(parts.len())?;
                parts[at].push_str(&below(10)?.to_string());
            }
            Ok(Secret::new(parts.join(separator)))
        }
        Recipe::Pin { length } => {
            if !(4..=12).contains(length) {
                return Err(Failure::new("A PIN must have 4 to 12 digits"));
            }
            let digits: Vec<char> = DIGITS.chars().collect();
            Ok(Secret::new(
                (0..*length)
                    .map(|_| pick(&digits))
                    .collect::<Result<_, _>>()?,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_the_eff_large_list() {
        assert_eq!(words().len(), 7776);
    }

    #[test]
    fn random_meets_its_classes() {
        for _ in 0..200 {
            let p = generate(&Recipe::default()).unwrap();
            let p = p.expose();
            assert_eq!(p.chars().count(), 24);
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
            assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn memorable_and_pin() {
        let r = Recipe::Memorable {
            words: 4,
            separator: "-".into(),
            capitalize: true,
            number: true,
        };
        let p = generate(&r).unwrap();
        assert_eq!(p.expose().split('-').count(), 4);
        assert!(p.expose().chars().any(|c| c.is_ascii_digit()));
        assert!(entropy(&r) > 51.0);
        let pin = generate(&Recipe::Pin { length: 6 }).unwrap();
        assert!(pin.expose().len() == 6 && pin.expose().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn rejects_weak_recipes() {
        assert!(
            generate(&Recipe::Random {
                length: 4,
                digits: true,
                symbols: true,
                avoid_ambiguous: true
            })
            .is_err()
        );
        assert!(generate(&Recipe::Pin { length: 2 }).is_err());
    }

    #[test]
    fn below_is_roughly_uniform() {
        let mut counts = [0usize; 6];
        for _ in 0..6000 {
            counts[below(6).unwrap()] += 1;
        }
        assert!(
            counts.iter().all(|&c| (800..1200).contains(&c)),
            "{counts:?}"
        );
    }
}
