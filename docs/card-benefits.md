# Card benefits: which card to pay with

Status: **draft for discussion.** Nothing here is built.

At checkout, the extension suggests which of your cards earns the most at this merchant, and says
when a card isn't accepted there. The work is done on your device: the extension knows the site,
the vault knows which card products you hold, and two downloaded datasets know what each product
pays and what each merchant usually is. Nothing about the purchase leaves the computer.

Card terms come from [CardFacts](https://github.com/WeiqiZhou2002/cardfacts), an open dataset of
US card terms (CC0 data, MIT code). VisiPass builds only what CardFacts doesn't have: the merchant
map (§4).

## 1. Goals and non-goals

Goals:

1. **Honest estimates.** Card payouts depend on the merchant category code (MCC) that the
   merchant's bank assigns, which the browser cannot see. Every suggestion is labelled an estimate,
   names its assumption ("if amazon.com posts as online shopping"), and links the card's terms.
2. **Private.** Which cards you hold, your spending so far, your activations and how you value
   points stay in the vault. The downloaded data is identical for every user.
3. **No affiliate links,** and no field for one.
4. **Fix things upstream.** A wrong or missing card term is fixed in CardFacts, not patched in
   VisiPass.

Non-goals for the first version: business cards in the picker, non-US cards, sign-up bonus
tracking, statement credits, card-linked offers (Amex Offers, Chase Offers), and any server that
sees a purchase.

## 2. Using CardFacts

### 2.1 What it provides

One JSON file per card in `data/us/<issuer>/`, validated by `schema/card.schema.json`. Catalog
`2026.11.08-draft` (schema 3) covers 30 cards (20 personal, 10 business) from Amex, Capital One,
Chase, Citi, Discover, U.S. Bank and Wells Fargo.

Each card has `id`, `networks`, `rewards` (`program`, and `unit`: cash or points), `fees` (dated
versions, like earn rates), `earn_rates` and `sources`.

`networks` is `{values, status, source, last_verified, notes}`. `values` lists every network the
product is issued on (Capital One Venture has been both Visa and Mastercard). An entry with status
`to_verify` has an empty list, which means not yet confirmed, not "no network".

Each earn rate has a category from `vocab/earn-categories.json` and a
list of dated `versions`, each with:

| Field | Use in VisiPass |
|---|---|
| `effective_from` / `effective_to` | Use the version in effect today. |
| `status`, `last_verified`, `source` | Show "checked 28 Oct" and link the source in the suggestion. |
| `rate` | Percent for cash, points per dollar for points (a string, e.g. `"4"`). |
| `conditions.channels` | `any`, `direct`, `issuer_portal`. |
| `conditions.region` | e.g. `US`: skip on a site outside that country. |
| `conditions.requires_activation` | Count it only if the vault records the activation (§3). |
| `conditions.selection` | Rotating categories, or categories the cardholder picks. |
| `conditions.merchants` | Bonuses tied to named merchants. |
| `conditions.prepaid` | Prepaid bookings only (hotels, car rental through a portal). |
| `cap` | `amount`, `period`, `reset_basis`, `rate_after_cap`, `shared_with`. |

Its 26 earn categories are the vocabulary the merchant map uses too:
`dining groceries wholesale_clubs gas ev_charging travel flights hotels car_rental
vacation_rentals transit rideshare streaming drugstores online_retail home_improvement
entertainment utilities telecom rent rotating everything_else shipping advertising office_supplies
software_cloud`.

### 2.2 How VisiPass takes it

CardFacts publishes catalog releases on GitHub (tagged `catalog-2026.11.08-draft`, marked
prerelease while the data is a draft), each with `cards.min.json` and `SHA256SUMS`. VisiPass:

1. Pins a release in this repository: `data/cardfacts.lock` holds the tag, `schema_version` and the
   SHA-256 of `cards.min.json`.
2. Downloads that asset in CI, checks the hash, and refuses a `schema_version` it doesn't know.
3. Ships it inside the extension, so a release of VisiPass is also the data release. A later
   version may fetch a newer signed snapshot between releases.

Moving the pin is an ordinary pull request that shows the diff of card terms, so a bad change
upstream reaches nobody until someone reviews it here. CardFacts also serves read-only JSON at
`https://weiqizhou2002.github.io/cardfacts/api/v1/`, rebuilt daily. It is handy for looking things up
and diffing revisions, but the extension never fetches it: daily files change without review here.

### 2.3 Gaps found so far, to fix upstream

- Networks. Asked upstream ([cardfacts#8](https://github.com/WeiqiZhou2002/cardfacts/issues/8))
  to source them from issuer terms and to allow a list. Both are done in schema 3: 15 cards are
  verified, and the other 15 (most Chase, Citi and Capital One cards) are `to_verify` while
  CardFacts sources them from pricing and terms, cardmember agreements and benefit guides. VisiPass
  needs this less than first thought: the network of the person's own card comes from its number
  (§3), and CardFacts' list is the fallback.
- Merchant exclusions (Amex grocery bonuses exclude superstores and warehouse clubs) are only in
  `notes`. The merchant map handles this from the other side: walmart.com is not `groceries`. If
  that proves insufficient, propose an `excludes` condition to CardFacts.
- The catalogue is still marked draft and has one maintainer, who answered #8 within two days and
  took both suggestions. If it stalls, the CC0 data can be forked and kept going.

## 3. What the vault stores

On a card item, beside number, expiry, name and CVV:

| Field | Example | Notes |
|---|---|---|
| `product` | `us-chase-freedom-flex` | A CardFacts `id`. Chosen from a list when the card is saved; imports can't fill it. |
| `activations` | `["2026-Q4"]` | Rotating periods the person has activated. |

The card's network is not stored: it comes from the number's leading digits (4 Visa, 51–55 and
2221–2720 Mastercard, 34 and 37 Amex, 6011 and 65 Discover), which is exact for that card even when
the product has been issued on more than one network. If CardFacts lists verified networks for the
`product` and the number's network isn't among them, the editor asks whether the product is right.

Per person, not per card:

| Setting | Default |
|---|---|
| Cents per point, per program | 1.0 (the cash-out floor, so points never look better than cash unless the person says so) |
| Spending so far, per capped category | unknown |

None of this is ever sent anywhere.

## 4. The merchant map (VisiPass's own data)

No open dataset maps websites to the category their purchases post as, or to the networks they
accept. This is VisiPass's contribution, published as its own repository under CC0 so other tools
can use it.

### 4.1 Layout

```
merchants/<site>.yaml   one merchant, named by its registrable domain
mcc.yaml                MCC → CardFacts category, for reading people's reports
schema/merchant.json    CI rejects anything that fails
```

A merchant is named by its registrable domain, using the Public Suffix List as the extension already
does for logins, so `www.costco.com` and `costco.com` are one file.

### 4.2 A merchant file

```yaml
site: costco.com
name: Costco
category: wholesale_clubs     # a CardFacts earn category
accepts: [visa, mastercard, discover]   # omit when every major network is accepted
observed:                     # counts of what people's statements showed; never who
  - { network: visa, mcc: 5300, reports: 0 }
notes: In U.S. warehouses Costco takes Visa only; this file covers costco.com.
sources:
  - https://customerservice.costco.com/   # illustrative
checked: 2026-11-01
verified: false
```

```yaml
site: walmart.com
name: Walmart
category: online_retail
not: [groceries]              # issuers that pay on groceries usually exclude this merchant
checked: 2026-11-01
verified: false
```

| Field | Meaning |
|---|---|
| `category` | What purchases here usually post as, from CardFacts' vocabulary. |
| `not` | Categories people might expect but issuers usually don't pay here. Shown as the reason a bonus was skipped. |
| `accepts` | Networks accepted online. Omitted means all. |
| `observed` | Reported `{network, mcc, reports}` counts. `mcc.yaml` turns each MCC into a category; when reports contradict `category`, CI flags the file for review. |
| `sources`, `checked`, `verified` | As in CardFacts: a person compared this to a source on that date. |

### 4.3 `mcc.yaml`

```yaml
5300: wholesale_clubs
5411: groceries
5541: gas
5542: gas
5811: dining
5812: dining
5813: dining
5814: dining
5912: drugstores
5942: online_retail
4511: flights
7011: hotels
```

Seeded from a public MCC list, such as [greggles/mcc-codes](https://github.com/greggles/mcc-codes),
and mapped by hand. It's used only to read reports, never at checkout, since the browser never sees
an MCC.

### 4.4 Reports

After a purchase, the person can look at their statement and report "this posted as 5300 on Visa".
The extension opens a prefilled issue on the merchant repository with only the site, network and
code: no amount, date, card or account. Maintainers merge counts into `observed`.

### 4.5 A merchant with no file

The suggestion says "category unknown" and ranks by each card's `everything_else` rate. The page's
own markup (schema.org `Restaurant`, `GroceryStore`) may be used as a hint later (§7).

## 5. How a suggestion is computed

For each card in the vault that has a `product`:

1. **Category.** From the merchant file, or unknown.
2. **Acceptance.** The card's network comes from its number (§3); without a number, from CardFacts
   when `networks` is verified with a single value. If the merchant's `accepts` excludes it, keep
   the card in the list as "not accepted here" and don't rank it. This is the "good card, but
   restricted" case. When the network is unknown (no number, and `to_verify` or several values),
   rank the card and say "check this site takes it" instead of guessing.
3. **Matching rates.** From the card's CardFacts record, take each earn rate's version in effect
   today whose category matches, or whose `conditions.merchants` names this merchant. Skip it when:
   - its category is in the merchant's `not`
   - it `requires_activation` and the vault has no activation for this period
   - its `region` doesn't match the site
   - its channel is only `issuer_portal` and the site isn't that portal
   - it's `prepaid`-only

   Rates limited to `direct` are kept, with "if booked directly" shown.
4. **Caps.** With the person's spending estimate, apply `rate_after_cap` once the cap is passed.
   Without one, show "5%, up to $1,500 this quarter".
5. **Value.** Cash rates as they are; points times the person's cents per point.
6. **Foreign fee.** Subtract `foreign_transaction_fee_percent` from the fee version in effect today
   when the site is outside the card's country. A null fee is unknown, not zero: say so rather than
   subtract nothing silently.

Cards are ranked by cents per dollar. When two are within 0.25¢, both are shown with what differs
(cash or points, which program, a cap nearly used), and the person picks. Otherwise the best card
is pre-selected, with one line on why, and filled when the person confirms.

## 6. Checks

In VisiPass CI:

- The pinned release's `cards.min.json` matches the hash and `schema_version` in
  `data/cardfacts.lock`.
- Every category a merchant file names exists in the pinned CardFacts vocabulary.
- Tests rank fixed cases from real records: Amex Gold against Citi Double Cash at a restaurant, Blue
  Cash Preferred at walmart.com (bonus skipped, reason shown), Freedom Flex with and without
  activation, and a Visa-numbered Venture at a Visa-only merchant (accepted, though CardFacts lists
  both networks).

In the merchant repository:

- Every file validates, and every change updates `checked` and cites a source or reports.
- A file whose `observed` reports mostly disagree with `category` fails until reviewed.

## 7. Open questions

1. **Ownership.** Should the merchant map live under VisiOffice, or be offered to CardFacts as a
   second dataset? Offering it first is cheap and keeps one place for contributors.
2. **Page hints.** Is schema.org markup good enough to guess a category for an unknown merchant,
   or should unknown merchants just show base rates?
3. **Spending estimates.** Asking for spending per capped category is friction. Start without it
   ("up to $1,500 this quarter") and add it only if caps cause wrong picks in practice.
4. **Card storage first.** The picker needs card items with a `product` field, which VisiPass
   doesn't have yet. Card storage and checkout fill are a prerequisite and their own design.
