# VisiPass cryptographic design

Status: **draft for review**, not implemented. Nothing in `vp-crypto` or `vp-store` is written
until this document has been through an outside review. Today VisiPass stores no secrets of its
own: every value lives in 1Password and VisiPass reaches it through `op`.

This document covers the native vault (milestone M3): how a vault is encrypted on disk, how it is
unlocked, what the daemon holds in memory, and what an attacker gets in each case. Sync, sharing
and the web app are specified only far enough that the local format does not paint them into a
corner; each gets its own review before it ships.

Reviewers: the questions we most want answered are in [§12](#12-questions-for-reviewers). Section
numbers are stable; please cite them. §13 records what the internal review changed.

## 1. Goals and non-goals

Goals, in order:

1. A copy of the vault file alone, without the Secret Key, is useless: brute force means guessing
   128 random bits.
2. A copy of the vault file **with** the Secret Key (a stolen, powered-off laptop; a home-directory
   backup) costs an attacker one Argon2id evaluation at 256 MiB per password guess. No optional
   feature may silently lower this; one that does must say so where it is turned on.
3. Keys exist only inside `visipassd`, and only while unlocked; locking erases them. Plaintext
   values leave the daemon only as answers to granted requests (`vp read`, `vp run`, the app, the
   browser extension), never at rest.
4. No ciphertext or key wrapping can be moved, swapped, replayed, rolled back or deleted without
   detection (§7), and revoking a credential cuts off anyone who held it (§6.3).
5. One cipher suite per format version. No negotiation; unknown versions are rejected before any
   other processing.
6. Only primitives from widely used Rust crates, composed as described here. No home-made
   primitives.

Non-goals:

- **Malware running as the user while the vault is unlocked.** It can ask `visipassd` for values
  like any other process (a human still approves each new use), or keylog the master password at
  the next unlock. §6.1 narrows this; it does not claim to stop it.
- **Root, kernel or firmware compromise**, and physical attacks on a running, unlocked machine.
- **Hiding the shape of the vault.** Item counts, padded ciphertext sizes, version counters and
  day-granularity dates are visible to anyone with the file (§8.3).

## 2. Primitives

| Purpose | Primitive | Crate (audit status: to confirm in review) |
| --- | --- | --- |
| Password hashing | Argon2id (RFC 9106), v0x13 | `argon2` (RustCrypto) |
| Key derivation | HKDF-SHA-256 (RFC 5869) | `hkdf`, `sha2` |
| Authenticated encryption | XChaCha20-Poly1305 | `chacha20poly1305` |
| MAC | HMAC-SHA-256 | `hmac` |
| Signatures | Ed25519 | `ed25519-dalek` |
| Key encapsulation (sharing, later) | HPKE (RFC 9180) with the X-Wing hybrid KEM (X25519 + ML-KEM-768) | to choose (§11.2) |
| Randomness | OS CSPRNG | `getrandom` |
| Key hygiene | | `zeroize`, `secrecy` |

### 2.1 Encodings

Every associated-data string, signed message and hash input in this document is the
**deterministic CBOR** (RFC 8949 §4.2) encoding of an array whose first two elements are a
context label (text) and `format_version` (unsigned integer). This document writes it as
`AD("label", a, b, ...)`. Fixed and variable-length fields (1Password alias IDs, for example)
are therefore never ambiguous. A ciphertext whose header names an unknown `format_version` is
rejected before any key is touched.

## 3. Secrets the user holds

- **Master password**, chosen by the user. Normalised to Unicode NFKD (the normalisation crate's
  Unicode version is pinned, since unassigned code points normalise differently across versions);
  not trimmed. Minimum strength enforced at creation with a zxcvbn-style estimate, not
  composition rules.
- **Secret Key**: 128 bits from the OS CSPRNG, generated at account creation, never sent
  anywhere. Shown as `VP1-` plus 26 Crockford base32 characters (130 bits; the top 2 are zero)
  and a 2-character checksum, grouped for reading. Stored on each device (§4.4) and printed on
  the Emergency Kit.
- **Recovery Key** (opt-in, §5.2): another 128 random bits, printed only, on a **separate sheet**
  from the Secret Key.

The Secret Key is what makes goal 1 hold. It does nothing against an attacker who has the device,
because the device stores it; there goal 2 applies and the master password carries the weight.

## 4. Unlock

### 4.1 Account Unlock Key

```
salt     = 16 random bytes per account, stored in the clear, replaced on every re-wrap
params   = { m: 262144 KiB (256 MiB), t: 3, p: 4 }, stored in the clear
pw_key   = Argon2id(NFKD(master_password), salt, params, out = 32 bytes)
PRK      = HKDF-Extract(salt = secret_key, ikm = pw_key)
AUK      = HKDF-Expand(PRK, AD("VisiPass account unlock key", 1, account_id), 32)
auth_key = HKDF-Expand(PRK, AD("VisiPass server auth", 1, account_id), 32)    // sync only, §11.1
```

`account_id` is 16 random bytes fixed at creation. The Argon2 work applies to the password, the
low-entropy input. The Secret Key enters as the HKDF-Extract key, so PRK is a PRF output under a
uniformly random 128-bit key, and its entropy multiplies the search space for anyone without it.

**Parameter bounds.** Before running Argon2, `params` must satisfy 64 MiB ≤ m ≤ 2 GiB, 1 ≤ t ≤ 10,
1 ≤ p ≤ 8; anything else is refused. The parameters are also bound into the AK wrapping (§4.2),
but that check only happens after Argon2 has run, so without bounds a tampered file (or later, a
sync server) could make the daemon allocate gigabytes.

Parameters can be raised by re-wrapping (§6.3), never lowered without the user asking. Expected
cost is about 0.5 to 1 s per unlock on a recent laptop, to be measured, including whether the
`argon2` crate runs lanes in parallel. The web client (later) must support the same parameters or
the account cannot use it there.

### 4.2 Account Key

The AUK never encrypts data. It wraps a random **Account Key (AK)**:

```
AK         = 32 random bytes; ak_generation starts at 1
wrapped_AK = XChaCha20-Poly1305(AUK, nonce = random 24 bytes, AK,
                                AD("VisiPass account key", 1, account_id, ak_generation, params, salt))
```

Every other account-level key derives from AK:

```
vault_wrap_key  = HKDF-Expand(AK, AD("VisiPass vault key wrap", 1, account_id, ak_generation), 32)
fingerprint_key = HKDF-Expand(AK, AD("VisiPass fingerprint",    1, account_id, ak_generation), 32)
keyset_key      = HKDF-Expand(AK, AD("VisiPass keyset",         1, account_id, ak_generation), 32)
log_key         = HKDF-Expand(AK, AD("VisiPass access log",     1, account_id, ak_generation), 32)
```

The **keyset** is an Ed25519 signing key pair (and, when sharing ships, an X-Wing key pair),
generated at random, stored encrypted under `keyset_key` with
`AD("VisiPass keyset", 1, account_id, ak_generation)`.

### 4.3 Quick unlock

Typing a 256 MiB-Argon2 password many times a day pushes people towards weak passwords or very
long auto-lock times. Quick unlock persists nothing:

- After a full unlock, the daemon may keep AK in locked memory (§6.1) for a **quick-unlock
  window** (default 8 hours, off by default) while the vault is otherwise locked: VKs, overviews
  and derived keys are erased as usual.
- Within the window, unlocking needs a polkit check (fingerprint through fprintd, or the login
  password), after which the daemon re-derives everything from AK.
- The window ends on reboot, on hibernation, when it expires, and on `vp lock --full`.

Because nothing is written to disk, goal 2 is unaffected. What it does weaken: during the window,
an attacker who can make the daemon believe a polkit check passed, or who can read its memory as
root, gets AK. That is inside the non-goals, but the setting says so.

**Not in this version:** a persisted device key (in Secret Service or a file). Any same-user
process can read Secret Service items over D-Bus without a prompt, so a stored key there would
make the login keyring, not Argon2, the protection of a backed-up vault. A TPM2-sealed device key
with a PIN policy (so the TPM's anti-hammering limits guesses) and its expiry bound into the
wrapping's associated data is the candidate for a later version.

### 4.4 Where the Secret Key lives on a device

Default: `~/.local/share/visipass/secret-key`, mode 0600. A home-directory backup that contains
both this file and the vault is protected only by the master password (goal 2), and the app says
so when backups are mentioned. Secret Service is not used: it adds no barrier against same-user
processes, little against an offline attacker (the login keyring's own KDF is cheap, and an
autologin keyring may have an empty password), and it loses the key if the login password is
changed outside PAM. Optional TPM2 sealing of the Secret Key may come with §4.3's device key.

## 5. Emergency Kit and recovery

### 5.1 Emergency Kit

A printable page with the account ID, the Secret Key and a space to write the master password by
hand. Generated at creation and after every Secret Key change.

### 5.2 Recovery Key

Losing the master password and every copy of the Secret Key loses the vault. Opt-in at creation,
a **Recovery Key** wraps AK independently:

```
recovery_wrap       = HKDF-SHA-256(salt = recovery_key, ikm = account_id,
                                   info = AD("VisiPass recovery", 1), L = 32)
wrapped_AK_recovery = XChaCha20-Poly1305(recovery_wrap, nonce, AK,
                                         AD("VisiPass account key recovery", 1, account_id, ak_generation))
```

It is high-entropy, so no Argon2. It is printed on its own sheet, never stored on a device. Using
it forces a new master password and a new Secret Key, and runs a full rotation (§6.3). Revoking it
is also a full rotation, not just deleting the row: whoever held it may already have the VKs.

## 6. Keys in memory, locking and rotation

### 6.1 What the daemon holds

While unlocked, `visipassd` holds AK, the derived keys, every VK, and every decrypted overview.
Details are decrypted per request and erased when the response is sent. The password, pw_key, PRK
and AUK are erased as soon as AK is unwrapped.

Hardening (Linux first):

- `prctl(PR_SET_DUMPABLE, 0)` and `RLIMIT_CORE = 0` at start: no core dumps (systemd-coredump
  included), and `ptrace` and `/proc/<pid>/mem` are closed to other processes of the same user.
- Key material lives in a dedicated allocation: `memfd_secret` where the kernel offers it (pages
  removed from the kernel's direct map), otherwise `mmap` + `mlock` + `MADV_DONTDUMP`. Locked
  memory stays out of swap but **not** out of a hibernation image; see §6.2.
- Key types are `secrecy` wrappers with `zeroize` on drop and no `Debug`/`Display`. Details are
  decoded straight into zeroizing buffers sized up front, so serde and `Vec` growth do not leave
  stray copies; IPC buffers that carried a value are zeroized after sending.
- Overviews are ordinary heap memory; their exposure to swap is accepted (§8.3).

Clients (`vp`, the app, the extension's native host) never receive keys, only the values a
granted request returns.

### 6.2 Locking

The daemon locks (erases AK unless a quick-unlock window is open, all derived keys, VKs and
overviews; grants are kept but unusable) on:

- idle timeout: default 10 minutes without a request, configurable;
- **suspend and hibernate**: the daemon holds a logind *delay* inhibitor for sleep and erases
  everything (including AK; quick unlock does not survive hibernation) before releasing it, so
  keys are gone before the hibernation image is written;
- **screen lock**: logind's `Lock` signal and `LockedHint` property. Some desktops lock without
  telling logind. Omarchy's `omarchy-system-lock`, for one, calls its own locker and then locks
  1Password directly with `1password --lock`; on Omarchy, VisiPass installs a lock hook running
  `vp lock`, and we will propose the same line upstream;
- `vp lock`, and quitting the app if the user chose that.

The approval rules (grants, per-agent scopes) are unchanged: a locked vault first asks the human
to unlock, then evaluates the request as today.

### 6.3 Changing credentials and rotating keys

Two different operations, and the app names them differently:

- **Change password** (or Secret Key, or Argon2 parameters): new salt, new AUK, re-wrap AK. Fast.
  It protects against nobody who already has an old copy of the vault file and the old password
  (they still unwrap the old `wrapped_AK`, hence the same AK and VKs), and the app says so.
- **Full rotation** ("my password or a backup may be compromised", and every revocation):
  1. new AK (`ak_generation + 1`), new keyset;
  2. new VK for every vault (`vk_generation + 1`), re-encrypting every item, history row,
     attribute block and attachment key;
  3. re-sign every manifest (§7) with the new keyset; old signing keys are retired;
  4. re-wrap AK under the new AUK, and the Recovery Key if kept.
  All in one SQLite transaction. After it, someone holding old keys can read only the old copy
  they already had, and cannot forge manifests or log signatures.

## 7. Vaults, items and integrity

### 7.1 Vault keys

Each vault has a random 256-bit **Vault Key (VK)**, wrapped symmetrically for its owner:

```
wrapped_VK = XChaCha20-Poly1305(vault_wrap_key, nonce, VK,
                                AD("VisiPass vault key", 1, account_id, vault_id, vk_generation))
vk_commit  = SHA-256(AD("VisiPass vault key commitment", 1, vault_id, vk_generation, VK))
```

`vk_commit` goes into the vault manifest (§7.4). It makes the AEAD effectively key-committing for
a vault: every reader checks the VK they hold against it, so two members cannot be given different
keys that decrypt one ciphertext to different plaintexts. Not needed while vaults are single-user;
built in now so sharing does not change the format.

### 7.2 Items

An item is two ciphertexts, as in 1Password:

- **overview**: title, URLs, tags, username, category, favourite flag, and the item's password
  fingerprints (§9). Decrypted for every item at unlock to build the search index, and kept
  decrypted while unlocked.
- **details**: every field value, notes, TOTP seeds, passkeys, SSH private keys, attachment keys.
  Decrypted per request.

```
ciphertext = header ‖ XChaCha20-Poly1305(VK, nonce = random 24 bytes, pad(cbor(part)),
                                         AD("VisiPass item", 1, vault_id, vk_generation,
                                            item_id, part, item_version))
header     = "VP" ‖ format_version (1 byte) ‖ vk_generation (4 bytes, big-endian) ‖ nonce
part       = "overview" | "details"
```

The associated data stops a ciphertext being replayed into another vault, item, part, version or
key generation. `item_version` increments on every save. Random 192-bit nonces need no
coordination between devices; the collision probability stays negligible at any realistic count.

### 7.3 History and deletion

Saving never overwrites: the previous details ciphertext becomes a history row bound to its own
`item_version`. Restoring writes a new version. Deleting an item writes a **tombstone** (item ID,
final version, deletion date) that stays in the manifest, so sync can tell "deleted" from "never
seen" and a deletion cannot be undone by replaying the old row. History is removed only by an
explicit purge, which is itself a manifest change.

### 7.4 Manifests

Per-row associated data cannot stop someone who can write the file from deleting a row, or
putting back an older valid one. Manifests cover everything:

```
vault_manifest = {
  vault_id, vk_generation, vk_commit, sequence,           // sequence: +1 on every change to the vault
  attrs:      H(attrs_ciphertext),
  wrapped_vk: H(wrapped_VK),
  items:      [(item_id, item_version, H(overview_ct), H(details_ct)), ...],   // sorted by item_id
  history:    [(item_id, item_version, H(details_ct)), ...],
  tombstones: [(item_id, final_version, date), ...],
  files:      [(file_id, file_version, H(file_ct)), ...],
}
account_manifest = {
  account_id, ak_generation, sequence,
  vaults: [(vault_id, vault_manifest.sequence, H(vault_manifest)), ...],
  account_row: H(wrapped_AK ‖ params ‖ salt ‖ keyset_ct ‖ wrapped_AK_recovery?),
}
H(x)      = SHA-256(AD("VisiPass manifest entry", 1, x))
signature = Ed25519(keyset signing key, AD("VisiPass manifest", 1, cbor(manifest)))
```

Checks:

- At unlock: signatures verify, and every row in the database matches the manifests exactly (no
  extra, missing or different rows).
- On every details read while unlocked: the ciphertext's hash matches the in-memory manifest. A
  row swapped under a running daemon fails here, not just at the next unlock.
- Rollback: the daemon keeps the highest account `sequence` it has seen in
  `~/.local/state/visipass/sequence`, written and fsynced **after** the database transaction
  commits. A database whose sequence is lower is refused, unless the user explicitly restores a
  backup. A crash between commit and fsync leaves the file one behind, which only weakens the
  check, never blocks a valid database.

Locally this defends against a tampered or swapped database file, not against someone who can
also rewrite the sequence file and the binary. Its real purpose is sync, where the server is
untrusted (§11.1).

### 7.5 Files

Attachments use the STREAM construction (chunked XChaCha20-Poly1305, 64 KiB chunks, final-chunk
flag), with a **fresh random key for every file version**. The key, the plaintext length and the
ciphertext hash are stored in the item's details, and the file is listed in the vault manifest,
so an older attachment cannot be swapped back in. The exact chunk format is specified when
attachments are built.

## 8. Storage

### 8.1 Layout

One SQLite database per account: `~/.local/share/visipass/<account_id>.vpdb`. Clear columns hold
only what is needed to find ciphertexts: random IDs, generations, versions, sequence numbers and
dates. Vault names, item titles and everything else a human typed are inside ciphertexts.

```
account(account_id, format_version, ak_generation, salt, params, wrapped_AK,
        wrapped_AK_recovery?, keyset_ciphertext, account_manifest, manifest_signature)
vault(vault_id, vk_generation, wrapped_VK, attrs_ciphertext, manifest, manifest_signature)
item(vault_id, item_id, item_version, overview_ciphertext, details_ciphertext, updated_on)
history(vault_id, item_id, item_version, details_ciphertext, created_on)
tombstone(vault_id, item_id, final_version, deleted_on)
file(vault_id, file_id, file_version, ciphertext)
```

### 8.2 Padding

Plaintext is `u32 length (big-endian) ‖ data ‖ zero bytes` up to a bucket size, and the length
prefix, not the padding, says where data ends. Buckets: the smallest multiple of 256 bytes that
fits, up to 4096; above that, the smallest power of two that fits. A short password and a long one
then look the same. Cheap locally, and the same ciphertexts are what a sync server would see.

### 8.3 What the file reveals

Without keys: the number of vaults, items, history rows, tombstones and files; padded sizes;
version counters and sequence numbers; and dates (day granularity; times of day are not stored in
the clear). Decrypted overviews in daemon memory may reach swap; `vp doctor` reports whether swap
is encrypted or absent.

## 9. Fingerprints for reuse and breach checks

To find reused passwords without decrypting every item's details, each item's overview holds
`HMAC-SHA-256(fingerprint_key, AD("VisiPass password fingerprint", 1, value))` for each password
field. Fingerprints are encrypted at rest with the overview and compared in memory. Never a bare
hash.

Breach checks use Have I Been Pwned's k-anonymity range API with `Add-Padding: true`: the SHA-1 of
the password is computed in memory, its first five hex characters are sent, the rest is compared
locally, and nothing is stored. Off by default; the first use asks.

## 10. Access log

Already built (M0) as a hash chain, holding no values. With the native store:

- Entries name items by ID. The item title, which today is in the clear, moves into a field
  encrypted under `log_key`, so `vp log` shows titles while unlocked and IDs while locked.
- The daemon signs the chain head after **every** entry with the keyset's Ed25519 key, using
  `AD("VisiPass access log", 1, account_id, entry_index, head_hash)`. Truncating or editing the
  log, including its newest entries, fails verification.
- While the vault is locked the signing key is unavailable, so entries written while locked
  (refusals, unlock prompts) are chained but unsigned until the next unlock signs the head; the
  daemon keeps the last signed head in memory to detect truncation of that tail.

## 11. Later: sync, sharing, web

Constraints the local design keeps possible. Each gets its own design and review.

### 11.1 Sync

The server stores the same ciphertexts, tombstones and signed manifests, and never holds AK, a VK
or the Secret Key. Clients authenticate with `auth_key` (§4.1), a separate derivation from the
AUK. It is high-entropy, so OPAQUE (`opaque-ke`) adds little over a simpler token scheme; OPAQUE
remains acceptable if it does not complicate the web client. Clients verify every manifest,
refuse sequence or generation rollback, and treat timestamps as hints. The server can withhold
updates or delete everything; every device keeps a full copy, so the latter is an outage, not a
loss.

### 11.2 Sharing

- Each account adds an **X-Wing** (X25519 + ML-KEM-768) key pair to its keyset, cross-signed by
  its Ed25519 key. Wrapped vault keys sit on a server for years, so the encapsulation is hybrid
  post-quantum from the start; signatures can stay classical.
- Sharing a vault encapsulates its VK to the recipient with HPKE, with info
  `AD("VisiPass vault share", 1, vault_id, vk_generation, vk_commit, sharer_id, recipient_id)`.
  The sharer signs the encapsulated key, ciphertext and info together.
- The vault **owner** signs a membership list (member IDs, their public keys, roles, the current
  `vk_generation`) with a monotonic counter. Clients accept manifests only from members the
  current list allows to write, and refuse writes under any generation but the latest, so a server
  cannot keep a member encrypting under a key a removed member knows.
- Public keys come from the server, so first contact needs out-of-band verification: a safety
  number over both of the contact's keys, compared in person or on a call.
- Removing a member rotates the VK (§6.3, step 2, for that vault).

### 11.3 Web app

Whoever controls the server that serves the web app's code can change it to steal the master
password. The web app will be served from a separate static host with reproducible, signed
builds, and documented as less secure than the desktop app. Argon2 at 256 MiB in WASM must be
measured, mobile Safari especially, before the web app is promised.

## 12. Questions for reviewers

1. **Unlock derivation (§4.1).** Secret Key as the HKDF-Extract key over the Argon2 output, AUK
   and `auth_key` expanded from one PRK. Sound?
2. **Secret Key storage (§4.4).** A 0600 file by default, Secret Service rejected. Agree? Is TPM2
   sealing worth doing early?
3. **Key commitment (§7.1).** Is `vk_commit` in the signed manifest sufficient, or should items
   use a committing AEAD construction directly once sharing exists?
4. **Argon2id parameters (§4.1).** 256 MiB, t=3, p=4 with the stated bounds. Right for desktop?
   What should the web client do if it cannot afford them?
5. **Recovery Key (§5.2).** Opt-in, printed separately, and its use or revocation forces a full
   rotation. A sound trade for a single user?
6. **Quick unlock (§4.3).** Is a memory-only window gated by polkit worth having, given that
   polkit's answer comes over D-Bus to a same-user daemon?
7. **Manifests (§7.4).** Is the coverage complete? Is checking details hashes on every read,
   plus the external sequence file, the right local rollback defence?
8. **Sharing (§11.2).** X-Wing through HPKE, owner-signed membership, `vk_commit` in the share
   info: anything missing before this is designed in detail?
9. **Memory (§6.1, §6.2).** Is `memfd_secret`/`mlock` plus a sleep delay inhibitor a reasonable
   baseline? Anything else for keeping keys out of hibernation images?
10. **Access log (§10).** Signing after every entry: any problem with signing many messages under
    one Ed25519 key in a hash chain?

## 13. Review record

1. **Internal adversarial review, 2026-10-12** (a separate model instance, not an outside
   cryptographer). Changes it caused:
   - Credential change and revocation now distinguish a fast re-wrap from a full rotation (new
     AK, VKs and keyset); revocation is always a full rotation (§5.2, §6.3).
   - Persisted device keys dropped: Secret Service gives no barrier against same-user processes
     and would have made the login keyring the real protection of a backed-up vault. Replaced by
     a memory-only quick-unlock window (§4.3). Secret Key moved to a file by default (§4.4).
   - Manifests extended to history, attributes, wrapped keys, tombstones and files, with an
     account manifest, per-read hash checks and a defined commit/fsync order (§7.4).
   - Sharing: `vk_commit`, owner-signed membership with generations, signed HPKE shares,
     cross-signed keys, X-Wing from the start (§7.1, §11.2).
   - Memory: `RLIMIT_CORE`, `memfd_secret`/`MADV_DONTDUMP`, a sleep delay inhibitor, zeroizing
     decode; goal 3 reworded to admit that granted values leave the daemon (§1, §6).
   - Screen lock: logind signals plus a `vp lock` hook, since Omarchy's lock does not tell logind
     (§6.2).
   - Argon2 parameter bounds checked before evaluation (§4.1).
   - One deterministic-CBOR encoding for all associated data, signatures and hashes, carrying
     `format_version` and key generations (§2.1).
   - HKDF used correctly (Extract before Expand); `auth_key` derived from the same PRK (§4.1).
   - Fingerprints moved to the overview so reuse checks do not decrypt details; HIBP padding on
     (§9).
   - Access-log titles encrypted; the head signed after every entry (§10).
   - Padding and buckets specified exactly; clear dates coarsened to the day (§8).
   - Attachments: fresh key per version, hash and length in details, listed in the manifest
     (§7.5).
2. **Outside design review**: one paid day with a cryptographer, before any `vp-crypto` code.
3. Robert's own data moves to the native store after step 2, with 1Password kept as the backup.
4. **Code audit** of `vp-crypto`, `vp-store`, sync and the server before anyone else's data,
   published in full.

## Changelog

- 2026-10-12: first draft; revised the same day after the internal review (§13).
