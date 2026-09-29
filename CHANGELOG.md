# Changelog

Semantic versioning. While the LUD-25 draft is unmerged, `0.x` minor bumps may
carry breaking changes; pin an exact version.

## Unreleased

**Breaking.** The address branch moves, so a `cx1` from 0.1.0 names a
different branch, and `ck1` and address proofs change format again: a `ck1`
now signs for one mint's domain, a note is filed under `hex(Q)`, and every
call that signs or verifies a `ck1` or an address proof takes the mint's
domain. A 0.1.0 `ck1` stays readable so its note can be rotated.

### Derivation purposes, `c` and `text/cpub` (LUD-25 `50d740a`)

Brought to luds `50d740a` (2026-09-25), graded against
`lnurlcash-conformance` 0.15.0.

- **Breaking: the note tweak takes a purpose.** `t = tagged_hash("LNURLcash/
  derive", P || chaincode || ser32(purpose) || ser32(i)) mod n`, so every note
  key moves. `derive_note_pubkey` and `derive_note_secret_key` take
  `purpose`, a keyword-friendly fourth argument defaulting to `PURPOSE_WALLET`
  (0: a wallet's own notes and a split's `p1`); `PURPOSE_CHANGE` (1) is a
  split's change `p2` and `PURPOSE_LIGHTNING_ADDRESS` (2) is a note credited by
  Lightning Address auto-mint or an internal transfer. Each purpose has its
  own counter, so recovery scans all three. The address registration proof and
  the address key are purpose 0, index 0. One `cx1` still covers every
  purpose.
- **Certificates are `c` and `c2`**, not `sig` and `sig2`, in withdraw
  responses and on the informational GET, and a certified note URL carries
  `&c=<cs1>`. Requests and rewritten note URLs use the new names only. The
  legacy `sig`, `sig2` and `&sig=` are still READ, `c` winning where both are
  present, so a mint or a note from before the rename keeps working. The
  registration-proof request parameter stays `sig`.
- `text/xpub` is now `text/cpub` in the LUD-16 internal-transfer hint. This
  package neither builds nor reads payRequest metadata, so there is nothing to
  change here.

### Every note is a taproot output key (LUD-25 `6e865b1`)

LUD-25's unified taproot model (luds `6e865b1`, "unified taproot
verification"): every note is a BIP-341 output key `Q`, named `cp1<Q>` and
filed by the mint under `hex(Q)`, and a `k1` is a spend of it. A bearer note
is the one-leaf hashlock `OP_SHA256 <h> OP_EQUAL` under BIP-341's NUMS key, so
its 64-hex preimage and hex `h` keep working as short forms. Graded against
`lnurlcash-conformance` 0.14.0: LUD-25's own vectors 1 to 5, the new
`spends.json`, and the regenerated `part2.json` and `nostr-seed.json`, plus
the mock mint's new model. No dependency was added: `coincurve` already signs
and verifies BIP-340 with a chosen `aux_rand`, and the canonical spend
transaction never changes shape, so its sighash is built by hand.

- New `lnurlcash_kit.spend`: `spend_domain_of`, `spend_prevout`,
  `spend_sig_msg`, `key_path_sighash`, `script_path_sighash`,
  `tap_leaf_hash`, `taproot_tweak`, `output_key_of` (merkle fold, tweak and
  parity check), `is_x_only_point`, `NUMS_KEY`, `bearer_leaf`, `bearer_note`,
  `bearer_note_id`, `bearer_cw1`, the `Cw1` codec (`encode_cw1`,
  `decode_cw1`, `is_cw1`, `output_key_of_cw1`), `check_leaf_policy` and
  `check_time_claim`. In `recoverable`, `decode_spend` and `verify_spend`,
  which checks a spend the way a mint would, time claims aside. There is no
  script interpreter: a `cw1` whose leaf is not a bearer hashlock is checked
  for structure, `Q` and the leaf rules and reported `unevaluated`.
- `sign_note_ownership(sk, domain)` signs the key-path sighash for the mint's
  domain, with all-zero `aux_rand`, so a key has one `ck1` per mint and it
  fails at every other. `recover_note_ownership_pubkey(payload, domain)`
  returns `NoteOwnership(pubkey_x_only, legacy)`, still reading `ck1`s signed
  over `sha256("LNURLcash")`, over the raw string, and the 65-byte
  recoverable shape, reported `legacy`. `note_ownership_message` is removed.
- `note_id_of` returns `hex(Q)` for every spend, a bearer preimage included
  (it was `sha256(k1)`), and names the note without verifying the spend.
  `note_lookup_of` gives a bearer preimage's `h`, or a `cp1` for anything
  else.
- Certificates are over `hex(Q)` for every note. `verify_note_signature(k1,
  domain, amount_msat, sig, mint_pubkey)` checks the spend opens its note at
  the domain, then the certificate, and returns a `Certification`:
  `CERTIFIED_OVER_Q`, `CERTIFIED_OVER_HASH` for a bearer note certified over
  its `h` by a mint from before taproot, or `NOT_CERTIFIED`, the only falsy
  one. `verify_note_signature_hash` now takes a bearer note's `h` (over `Q`,
  then `h`); the new `verify_note_signature_for_key` takes `hex(Q)`, for a
  watcher. New `verify_note_url` makes the whole offline check from a note
  URL.
- `address_proof_message`, `address_proof_digest` and `sign_address_proof`
  take the mint's domain: `LNURLcash:<action>:<domain>:<username>`.
- Outputs go as `p1`/`p2` and lookups as `p` whatever they are, a `cp1` or a
  bearer `h`, as LUD-25 spells them (a hex `h` went as `h`/`h2` and `?h=`).
  Every current mint reads both spellings.
- A `cp1` whose key is not a curve point no longer decodes, so a mint invoice
  to one is refused before anything is paid.
- `resolve_note_input` and the informational GET's echo check verify the
  spend at the note URL's own domain, so a `ck1` for another mint, or the
  right key under a broken signature, is not taken for the note.
- `OutputInUse`, a `ServiceRejected`, is LUD-25's `already in use`: an
  output is taken, nothing was burned, and it carries no secrets. Matched as
  a phrase, so lnurl-mint's `Output already in use.` counts too.
- A note tweak `t >= n` is reduced mod n, as LUD-25 requires and
  lnurl-wallet does, instead of refusing the index. A ~2^-128 event.
- An output named by a `cp1` still owes its `cs1` whatever the `Policy`,
  although LUD-25 now makes certification a SHOULD for every note: offline
  verification is the reason to name a note that way.
- CI and the release workflow pin `lnurlcash-conformance` `v0.14.0`.

### Ownership and address proofs sign a sha256 digest, not the raw message

BIP-340's own reference implementation, and most conforming Schnorr signers
(`libsecp256k1`'s `schnorrsig` module, which `coincurve` wraps, included), only
accept a 32-byte message. Matches `lnurl-wallet#167`/`#168` and
`luds#6de59b2`.

- `sign_note_ownership` signs `sha256("LNURLcash")`.
  `recover_note_ownership_pubkey` verifies against that digest first, then
  falls back to the pre-2026-09-16 raw-message scheme so a note minted under
  it stays redeemable until it is rotated - `sign_note_ownership` never
  produces that shape, only reads it back.
- `sign_address_proof` signs `address_proof_digest`, now `sha256(message)`,
  for the same reason: `username` is variable-length, so the raw message
  would otherwise only rarely land on 32 bytes. No fallback here - a
  register/unregister proof is a fresh action a wallet initiates itself,
  never a stored bearer secret read back later.
- Add `address_proof_message`, the exact UTF-8 string the digest is taken
  over, and `note_ownership_message`.
- Graded against `lnurlcash-conformance` 0.13.0's regenerated Part 2, Nostr-
  seed and spec vectors, including `spec-vectors.json`, LUD-25's own
  published Test Vectors.

### BIP-340 wallet ownership proofs

- Follow the revised LUD-25 `ck1` format: a 96-byte payload containing the
  32-byte x-only note key and a 64-byte BIP-340 signature, made with all-zero
  auxiliary input so seed recovery reproduces it byte for byte. `cs1` remains
  recoverable ECDSA and is unchanged.
- `sign_note_ownership` returns that complete 96-byte payload;
  `recover_note_ownership_pubkey` verifies the embedded signature before
  returning its key. `encode_ck1` requires the 96-byte current payload.
- `decode_ck1`, `is_ck1`, `note_id_of`, `note_lookup_of` and verification
  continue accepting the old 65-byte recoverable-ECDSA form so existing
  bearer notes can be rotated; the decoded length says which shape was read.
  New signing and encoding only emit the Schnorr form.
- `sign_address_proof` returns a 64-byte BIP-340 signature instead of
  `r || s || recovery-id`.
- A `ck1` is now one string per key, so the high-S twin no longer exists;
  `note_info_request` still compares an echoed `ck1` by its verified note key.

### The address branch has no separate purpose

- `derive_cash_address_node` is now the literal `m/139'/d1/d2/d3/d4` path
  LUD-25's text specifies, with the hashing key at `m/139'/0`: exactly
  `derive_cash_domain_node`. `derive_nostr_address_node` follows it. The
  earlier `m/139'/1'` hop only existed to dodge a collision with a
  now-removed Part 1 seed-derivation extension that was never part of the
  spec.
- `cash_secret_at`, `derive_cash_secret` and `CashSecretSource` are removed
  along with that extension; Part 1 notes are plain randomness, as LUD-25's
  own text always specified. `derive_note_root`/`derive_note_secret`, the
  pre-spec HMAC scheme, are unchanged.

## 0.1.0 — 2026-09-15

### Reference address proofs and compact note URLs

- Add `address_proof_digest` and `sign_address_proof` for the reference
  mint's signed register/update/unregister flow, using the address branch's
  index-0 key and binding the proof to both action and normalised username.
- Read the declared amount from an amount-bearing `cs1` when no separate
  `amount` exists, and omit that duplicate parameter when rebuilding a URL
  carrying a current certificate.
- Grade both behaviours against `lnurlcash-conformance` 0.11.0 vectors.

### Amount-bearing mint certificates

- Add `encode_cs1_with_amount`, `decode_cs1_with_amount` and
  `is_cs1_with_amount` for the current wire format, whose prefix carries the
  amount with BOLT 11 amount rules. Decoding returns the new frozen `Cs1`
  dataclass.
- Keep `encode_cs1`, `decode_cs1` and `is_cs1` unchanged for legacy
  fixed-prefix certificates. Add `decode_any_cs1` and `is_any_cs1` for
  migrations accepting both forms.
- Signature verification accepts both formats, matching the reference kit;
  callers can decode and compare the carried amount separately when needed.
- Grade the current format against `lnurlcash-conformance` 0.11.0 vectors.

### Amounts are read exactly

- An informational GET, by secret or by hash, whose `maxWithdrawable` or
  `minWithdrawable` is past 2^53 - 1 now raises `ProtocolError`. A Python int
  has no ceiling, so 18446744073709552000 used to be taken at its word; past
  2^53 the number a SERVICE wrote need not be the number it meant. The same
  bound the fee parser and lnurlcash-kit already apply. A fraction was, and
  is, refused.
- Graded against `lnurlcash-conformance` 0.10.0's `withdraw-info.json`, every
  case, through the client over a mock transport, including the request it
  sends: `sig` stays behind and `k1` goes out unchanged.

### No-signer legacy compatibility

The reference mint signs a legacy hash output with a raw Part 1 signature when
a signer is available and may omit it in no-signer mode. The committed
TypeScript reference wallet requires it; this library keeps a tolerant default
and exposes the strict behaviour as policy.

- `Policy.require_signatures` now defaults to **False**. In no-signer mode,
  `signature` (and `change_signature`) is `None` and nothing is raised. Set it
  true to match the strict reference wallet and demand the raw Part 1
  signature over the hash.
- A `cp1` output is owed its `cs1` certificate whatever the policy says. A
  rotate, split or merge naming one (sent as `p1`, or `p2` for a split's
  change) that comes back without `sig` (or `sig2` for a `cp1` change) raises
  `UnverifiableNote`. It carries no secrets: only the `*_with_hash` calls can
  name a `cp1` output, and their caller already holds the key.
- A signature that is present on a hash output is passed on as before, so a
  mint still issuing the Part 1 signature is fine where it verifies.
- New `Policy.require_mint_pubkey`, default True, takes over the
  `withdrawRequest` `mintPubkey` check that `require_signatures` used to
  carry, in `note_info_request` and `note_info_by_hash_request` alike. A Part
  1-only mint that publishes no `mintPubkey` is admitted with it set False.
- Graded against `lnurlcash-conformance` 0.10.0, which CI now pins. Every
  `responses.json` case is driven through the client for the first time,
  picking a `cp1` or a hash output by the case's `output` and `change`
  fields, and each bare "mutation" case through both rotate and merge.

If you relied on the default to refuse unsigned plain notes, pass
`Policy(require_signatures=True)`. If you only ever wanted notes a recipient
can verify offline, hold `cp1` notes: they are the only kind the spec makes
verifiable.

### LUD-25 Part 2: notes keyed by a public key

A Part 2 note is keyed by a public key rather than a hash. The holder keeps
`sk`, discloses `pk` as `cp1`, and spends the note with `ck1`, a recoverable
signature by `sk`; the mint recovers `pk` from it. The new
`lnurlcash_kit.recoverable` carries lnurlcash-kit's TypeScript names in
snake_case.

- The four bech32m encodings: `cp1` (a note's key), `ck1` (its bearer secret),
  `cs1` (the mint's certificate) and `cx1` (a watch-only branch), with
  `encode_*`, `decode_*` and `is_*` for each. Fixed lengths and no 90-character
  limit; all-uppercase is accepted and mixed case refused. Decoders return
  `None` rather than raise.
- `bech32` gains bech32m, BIP-350's constant beside BIP-173's. LUD-01 decoding
  is unchanged, and neither accepts the other's checksum.
- `derive_note_pubkey` (watch-only) and `derive_note_secret_key`, the per-note
  key tweak. The index is any uint32. A tweak at or above n, or a zero key,
  raises rather than being reduced: use the next index.
- `sign_note_ownership` and `recover_note_ownership_pubkey`.
- `derive_cash_address_node` and `cash_node_to_cx1`. The branch is
  `m/139'/1'/d1..d4`, which is what lnurl-wallet derives, not the
  `m/139'/d1..d4` the spec text gives.
- `note_id_of(k1)`, the id a mint files either kind of note under, and
  `note_lookup_of(k1)`, what to look it up by without disclosing it. One note
  has many valid `ck1` strings, so notes compare by id.
- `note_info_request` compares an echoed `k1` by the note it names, as every
  LNURLcash kit does. A SERVICE echoing another valid `ck1` for the same note,
  such as its high-S twin, is not mistaken for one that swapped the note; a
  different note is still refused.
- The wire takes both kinds. A `ck1` goes anywhere a `k1` does, and
  `resolve_note_input` accepts a note URL carrying one. A `cp1` output goes as
  `p1`/`p2` from the `*_with_hash` calls while a hash keeps `h`/`h2`;
  `mint_invoice_request_with_hash` sends one as the comment alone, and
  `build_note_info_url_by_hash` as `p`.
- `verify_note_signature` takes a `ck1` and a `cs1`.
  `verify_note_signature_hash`, `note_signature_message_for_hash` and
  `note_signature_digest_for_hash` do the same for a caller holding only the
  key, as a `cx1` watcher does. `note_signature_message` now raises
  `ProtocolError` for a k1 that is neither kind.
- `WithdrawRequestInfo` and `NoteInfoByHash` carry the response's `sig` as
  `signature`: for a Part 2 note, the mint's ready-made `cs1`.
- `derive_cash_master(seed)`, the BIP-32 master node.
- An extension, not LUD-25: `derive_nostr_cash_seed` and
  `derive_nostr_address_node`, a Part 2 branch rooted in a Nostr identity key
  (`HMAC-SHA256(key, "LNURLcash/nostr-seed")`, then the same path), as
  heartwood-esp32 derives it.
- Graded against `lnurlcash-conformance` 0.9.0's `part2.json` and
  `nostr-seed.json`: every field of every branch, note and certificate,
  including recovering each `ck1` to its key and each `cs1` to the mint's.

### Three more fields off a mint address

`mint_address_request` reads `nodeUris`, `sunsetDate` and
`outstandingNotesMsat`, which the reference mint publishes and this dropped.

- `node_uris` — every address the SERVICE's node announces. `node_uri` is the
  first of them; a node behind Tor as well as clearnet has more. `None` rather
  than an empty tuple when there are none.
- `sunset_date` — the day the SERVICE plans to close, ISO-8601. Validated with
  `date.fromisoformat` and dropped otherwise: the one thing a WALLET does with
  this is show it to a holder, and a wrong date is worse than no date.
- `outstanding_notes_msat` — what the SERVICE says it owes. `0` and `None` are
  different answers.

### Seed-recoverable note secrets, and the private lookup a restore needs

- `lnurlcash_kit.cash`: LUD-25's `m/139'` scheme. `derive_cash_root`,
  `derive_cash_domain_node`, `derive_cash_secret`, `cash_secret_at`,
  `cash_domain_indices`, `cash_node_to_hex`/`from_hex`, `derive_cash_child`
  and `CashSecretSource`. `d1..d4` are raw uint32 used exactly as they fall,
  hardened only where they land at or above 2^31; masking the top bit or
  hardening all four derives a different tree from every conforming wallet.
- `derive_note_root` / `derive_note_secret`: the pre-spec HMAC scheme, so
  notes minted under it stay findable. Not what to mint under.
- `build_note_info_url_by_hash` and `note_info_by_hash_request`: LUD-25's
  `?h=` informational GET. A restore walk queries a whole gap window of
  indices the wallet has not minted into yet, so asking by secret publishes
  exactly the secrets it is about to mint under.
- `NoteInfoByHash` is its own type rather than `WithdrawRequestInfo`: that
  type's `k1` is the bearer secret, and a conforming SERVICE has nothing to
  echo when the request never named one.
- Graded against `lnurlcash-conformance` 0.7.0's `cash-derivation.json` and
  `derivation.json`, including BIP-32's own published test vector 1.

First release. A Python implementation of LNURLcash, following the protocol
layer of dni's [lnurl-wallet](https://github.com/dni/lnurl-wallet) and checked
against the shared
[conformance vectors](https://github.com/lnurlcash/lnurlcash-conformance)
and the adversarial mock mint.

### Design notes

**A `cp1` note is owed its certificate, and this library insists on it.** For
a while LUD-25 required a signature over every note a rotate, split or merge
minted, and this library's default refused an unsigned one. The Part 2
rewrite introduced `cp1` certificates, so a mutation to a `cp1` output that
comes back without its `cs1` raises `UnverifiableNote`. A legacy hash carries
the raw Part 1 signature when a signer is available and may omit it in
no-signer mode. `note_info_request` refuses a `withdrawRequest`
publishing no `mintPubkey`, or one that is not a 33-byte compressed secp256k1
key, unless `Policy(require_mint_pubkey=False)`.
`Policy(require_signatures=True)` demands the raw signature over a hash.

That exception carries whatever fresh secrets the library generated, and the
reason matters: `status` was OK, so the mutation LANDED. The note exists at the
key or hash the wallet disclosed and that secret is the only key to it, so
enforcing the spec must never be the thing that strands the money.

**A spent-or-unknown refusal from a mutation carries its secrets too.** At a
SERVICE that has not implemented the replay rule below, a retried mutation is
answered as an already-spent input - so that refusal is also what a mutation
the SERVICE ALREADY applied looks like. `ServiceRejected` gained
`new_secrets`, and `new_secrets_of(err)` reads them off all three families that
can carry them. A refusal on policy grounds burned nothing and carries nothing.

**A mutation whose answer was lost is re-sent, and usually completes.** LUD-25
gained a "Retrying a mutation" section: a SERVICE MUST answer a byte-identical
rotate, split or merge with the success it already returned. Both clients
re-send - `mutation_retries`, default 1 - so a dropped connection resolves into
a completed mutation rather than an unresolved maybe.

A `Request` now says whether it is `replayable`, which only a rotate, split or
merge is. A melt never is: it carries `pr`, is paid asynchronously and has no
replay guarantee, so a second request could ask for a second payment. Only an
ambiguous failure is retried, and the same `Request` goes out each time rather
than a rebuilt one, because the replay is matched on the k1 set, `h`, `h2` and
`amount` - a regenerated secret would make the retry a different mutation, and
a second real burn.

**Minting is comment-bound, and the payment preimage is only settlement proof.**
The draft keyed a fresh note by the invoice's payment preimage until 31 August
2026, when that fallback was removed outright: a preimage propagates to every
node that forwarded the payment, routinely before the payer has finished
processing it, so a note keyed by one is a note all of them can spend. A WALLET
now chooses the secret itself, before any invoice exists, and hands the SERVICE
only `sha256(secret)` in a mandatory LUD-12 `comment`; a minting `payRequest`
must advertise `commentAllowed >= 64` or it cannot mint at all. `mint_invoice_request` returns the secret
on `Request.new_secrets` - persist it before paying, because the SERVICE holds
nothing that could reconstruct it.

**The mint address carries the node stats under their wire names.** lnurl-mint
advertises `nodeCapacity` in msat, so `node_capacity_msat` is a rename and is
mapped explicitly — the TypeScript sibling shipped that rename unmapped and
read `None` for every mint.

**`parse_mint_fee` refuses a component past 2^53**, which Python alone would
carry exactly. A fee has to mean the same thing in every implementation, and
the shared vectors refuse it, so accepting it here would make this the odd one
out rather than the generous one.



**The protocol has no I/O in it.** `lnurlcash_kit.protocol` describes each
operation as a `Request` — a URL, a parser, and the fresh secrets that must
survive a lost answer. The sync and async clients do nothing but perform the
GET, which is why they cannot drift apart, and why a caller with its own HTTP
stack can skip them entirely.

**`gross_up_for_mint_fee` is a binary search**, not an estimate-then-walk. At a
99.9999% fee a one-msat walk is around a million steps, so any guard on it
returns a non-minimal answer — and the fee is chosen by the service, so that
input is reachable on purpose.

**The proportional fee term is computed split**, as
`(g // 1e6) * ppm + ((g % 1e6) * ppm) // 1e6`. Python integers are arbitrary
precision so this changes nothing here; it is written this way deliberately so
that the Rust and Go ports, where a direct multiply overflows 64-bit unsigned
at realistic amounts, are doing visibly the same arithmetic.

**A service's `reason` is carried through exactly as sent**, empty string
included. Substituting a friendly default before classification would be read
back as though the service had said it: "Unknown service error" matches the
rule for an unknown note, and would report one on no evidence at all.

**bech32 is vendored** from the BIP-173 reference implementation rather than
taken as a dependency: sixty lines of checksum arithmetic with no crypto in
it, and a bearer-money library is better off with one fewer supply-chain edge.
