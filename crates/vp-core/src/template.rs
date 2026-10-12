//! `{{ op://vault/item/field }}` templates, as `op inject` reads them.

use crate::Failure;
use crate::refs::SecretRef;
use crate::secret::Secret;
use std::collections::HashMap;

enum Piece<'a> {
    Text(&'a str),
    Ref(SecretRef),
}

fn pieces(template: &str) -> Result<Vec<Piece<'_>>, Failure> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else { break };
        let inner = after[..end].trim();
        if SecretRef::is_reference(inner) {
            out.push(Piece::Text(&rest[..start]));
            out.push(Piece::Ref(SecretRef::parse(inner)?));
        } else {
            out.push(Piece::Text(&rest[..start + 2 + end + 2]));
        }
        rest = &after[end + 2..];
    }
    out.push(Piece::Text(rest));
    Ok(out)
}

pub fn references(template: &str) -> Result<Vec<SecretRef>, Failure> {
    let mut seen = Vec::new();
    for piece in pieces(template)? {
        if let Piece::Ref(r) = piece
            && !seen.contains(&r)
        {
            seen.push(r);
        }
    }
    Ok(seen)
}

pub fn render(template: &str, values: &HashMap<SecretRef, Secret>) -> Result<Secret, Failure> {
    let mut out = String::with_capacity(template.len());
    for piece in pieces(template)? {
        match piece {
            Piece::Text(text) => out.push_str(text),
            Piece::Ref(r) => out.push_str(
                values
                    .get(&r)
                    .ok_or_else(|| {
                        Failure::new("Secret resolver returned an unexpected number of values")
                    })?
                    .expose(),
            ),
        }
    }
    Ok(Secret::new(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_references_and_keeps_other_braces() {
        let t = "url: postgres://u:{{ op://V/DB/password }}@h\nother: {{ not a ref }}\nagain: {{op://V/DB/password}}";
        let r = SecretRef::parse("op://V/DB/password").unwrap();
        assert_eq!(references(t).unwrap(), vec![r.clone()]);
        let out = render(t, &HashMap::from([(r, Secret::new("pw".into()))])).unwrap();
        assert_eq!(
            out.expose(),
            "url: postgres://u:pw@h\nother: {{ not a ref }}\nagain: pw"
        );
    }
}
