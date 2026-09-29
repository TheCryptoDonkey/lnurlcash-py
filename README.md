# lnurlcash-kit (Python)

LNURLcash ([LUD-25 draft](https://github.com/lnurl/luds/pull/301)) bearer
notes for Python: mint, rotate, split, merge, melt, and verify a note offline.

```bash
pip install lnurlcash-kit
```

This is an early `0.x` release tracking a **draft** spec. Pin an exact
version.

## What a bearer note is

An ordinary [LUD-03](https://github.com/lnurl/luds/blob/luds/03.md)
withdrawRequest link whose `k1` **is** the asset:

```
lnurlw://mint.example/w?k1=<spend>&amount=<msat>
```

Whoever knows the `k1` controls the sats behind it, like a banknote. The
`amount` alongside it is only a claim by whoever encoded the note; the
authoritative value is always `maxWithdrawable` from an informational GET.
Every note is a BIP-341 taproot output key `Q`, and the `k1` is a spend of it:
see [Notes, spends and certificates](#notes-spends-and-certificates).

## Usage

```python
from lnurlcash_kit import LnurlcashClient, resolve_note_input, verify_note_signature

client = LnurlcashClient()

url = resolve_note_input(scanned)          # bech32, lnurlw://, or https
if url is None:
    raise ValueError("not a note")

info = client.fetch_note_info(url)         # what is it actually worth?
print(info.max_withdrawable, "msat")

fresh = client.rotate_note(info.callback, info.k1)   # that GET exposed the secret

# The mint certifies the new note over its hex(Q) when it has a signer, and
# omits the certificate when it has none.
if fresh.signature is not None:
    verify_note_signature(
        fresh.k1, url, info.max_withdrawable, fresh.signature, info.mint_pubkey
    )
```

`AsyncLnurlcashClient` has the identical surface with `await`. Both accept
`timeout`, `offline`, `rng`, `policy`, `mutation_retries`, and an existing
`httpx` client:

```python
async with httpx.AsyncClient() as http:
    client = AsyncLnurlcashClient(client=http, timeout=10.0)
    info = await client.fetch_note_info(url)
```

### Bring your own HTTP stack

Everything about the protocol lives in `lnurlcash_kit.protocol`, with no I/O
in it. Each operation is a `Request`: a URL to GET, a parser, and the fresh
secrets that must survive if the answer is lost.

```python
from lnurlcash_kit import protocol

req = protocol.rotate_request(callback, k1)
body = your_http_get(req.url)              # aiohttp, requests, anything
try:
    result = req.parse(body)
except AmbiguousMint:
    save(req.new_secrets)                  # first. always.
```

That is also why the sync and async clients cannot disagree about what a
response means: neither of them decides.

## The five things that will cost you money

**1. Never let the service generate a replacement secret.** On rotate, split
and merge the *wallet* draws a fresh 32-byte preimage and discloses only its
`h = sha256(preimage)`, as `p1` (and `p2`). A service-issued replacement has,
structurally, been seen by that service, so a "rotate" that accepts one
closes no exposure at all. This library generates them and ignores any `k1` a
non-compliant service hands back.

**2. A failed mutation is not a failure.** If a rotate times out, the service
may already have burned your input and minted the output, and the fresh
secret in your process is the only copy of that money in existence.

```python
try:
    result = client.rotate_note(callback, k1)
except AmbiguousMutation as err:
    save(err.new_secrets)                       # first. always.
    fate = client.probe_burned_note(note_url)
    # 'live'    -> nothing landed, the saved secrets are worthless
    # 'gone'    -> the burn landed, the saved secrets ARE the note
    # 'unknown' -> keep everything and try again later
```

`RequestRefused` is the opposite and safe: nothing left the process.

**3. A retried mutation is now a replay, not a double spend.** Every mutation
is a GET, HTTP treats GET as idempotent, and an LNURLcash mutation is not — the
first attempt burns the input. For most of this draft's life that was the
sharpest edge in the protocol: a stack that resent a dropped GET got "already
spent" for the second attempt, which reads as a *definitive* rejection, so the
fresh secret got discarded along with the note the service had just minted. The
hazard broke the [Kotlin](https://github.com/lnurlcash/lnurlcash-kotlin)
and [Go](https://github.com/lnurlcash/lnurlcash-go) siblings during
development, by two different mechanisms.

LUD-25 closed it. A service MUST answer a byte-identical rotate, split or merge
with the success it already returned, signatures and all where there were any.
So this library re-sends one whose answer was lost, and an unstoppable
transport retry is now simply invisible:

```python
# the connection dropped after the mint applied this. It completes anyway.
fresh = client.rotate_note(callback, old_k1)
```

`mutation_retries` sets how many times (default 1; `0` restores the old
give-up-at-once behaviour). Only rotate, split and merge are re-sent — never a
melt, which carries `pr`, is paid asynchronously and has no replay guarantee —
and only an ambiguous failure, never a refusal the service actually considered.
The re-sent request is byte-identical: the replay is matched on the notes the
`k1`s open, `p1`, `p2` and `amount`, and a fresh secret would make it a
different mutation.

`httpx` does not retry by default, which is still what this library wants: a
deliberate retry it counts is a different thing from an invisible one it does
not. If you pass your own client, do not configure a retrying transport.

**3b. An output named by a `cp1` is owed its certificate.** LUD-25 has a mint
certify every note with a `cs1` over its `hex(Q)`, a bearer note included; it
is a SHOULD, and a mint with no signer omits it. A rotate, split or merge to
an output named by a `cp1` that the service confirms without its `cs1` (in
`sig`, or `sig2` for a split's change) raises `UnverifiableNote`, whatever the
policy says: offline verification is the reason to name a note that way. An
output named by a bearer `h` may have `signature=None`.

`UnverifiableNote` **carries the fresh secrets** the library generated,
because the mutation landed and the note it minted is real. Read them with
`new_secrets_of` and persist them before anything else. It is empty after a
`*_with_hash` call, whose caller named the output and already holds its key.

Two `Policy` fields tune the rest. `require_signatures=True` demands a
certificate for an output named by a bearer `h` too. `require_mint_pubkey`
(default `True`) makes `fetch_note_info` raise `ProtocolError` for a
`withdrawRequest` publishing no valid `mintPubkey`; set it `False` for a mint
that publishes none.

```python
client = LnurlcashClient(policy=Policy(require_signatures=True))
```

**4. A melt's `OK` means "in flight", not "spent".** The service pays
asynchronously and only burns the note once the payment settles, restoring it
if the payment fails. A failed melt is never reported back through the
callback — it is only observable as the note becoming spendable again. Other
operations on that `k1` raise `NotePending` meanwhile; retry, never read it as
spent.

**5. Rotate the instant you claim a minted note.** The preimage that mints a
note is generated by the service, and if it serves
[LUD-21](https://github.com/lnurl/luds/blob/luds/21.md) `verify`, *anyone* who
saw the unpaid invoice can poll for it — the payment hash travels inside the
invoice. First rotater wins.

## Seed derivation

LUD-25 derives a per-mint branch of note keys from the wallet seed, and this
library implements the specified path:

```
cashHashingKey   = m/139'/0
(d1, d2, d3, d4) = HMAC-SHA256(cashHashingKey, host)[0..16] as 4 uint32
branch           = m/139'/d1/d2/d3/d4
```

`d1..d4` are used **exactly as they fall**. BIP-32 reads any index `>= 2^31`
as hardened, so which of the four levels are hardened is decided by the mint's
own host name. Masking the top bit, or hardening all four, derives a different
tree and restores nothing, silently.

```python
root = derive_cash_root(seed)                   # m/139'
node = derive_cash_domain_node(root, host)      # m/139'/d1/d2/d3/d4
```

That node is the address branch of key-path notes (`derive_cash_address_node`
returns the same one). Whoever holds it can derive every note key held at that
mint - provisioning material, one mint's subtree, not the wallet.

Bearer preimages are plain randomness, as LUD-25 says. They are not derived
from the seed, so back them up by other means or rotate them into a key.

`derive_note_root` / `derive_note_secret` are the pre-spec HMAC scheme this
project shipped before the draft had one. Not deprecated, because notes minted
under it are still money; just not what to mint under.
`note_info_by_hash_request` is the private lookup a restore walk should use:
asking by secret publishes the very secret being checked.

## Notes, spends and certificates

Every LUD-25 note is a BIP-341 taproot output key `Q`, written `cp1…`, and a
mint files it under `hex(Q)`. A `k1` is a spend that opens one:

- **A bearer note's preimage**, 64 hex. The note is the one-leaf hashlock
  `OP_SHA256 <h> OP_EQUAL` under BIP-341's NUMS key, so the preimage is the
  short form of its script-path spend, and `h = sha256(preimage)` is the short
  form of its `cp1`. It signs nothing, so it spends its note at any mint.
- **A `ck1`**: `Q` and a BIP-340 signature by `Q` over the key-path sighash of
  a fixed, never-broadcast transaction whose prevout is bound to the mint's
  domain. It spends its note at that mint and nowhere else.
- **A `cw1`**: a leaf, its control block and the witness the leaf consumes,
  for any script tree. `Q` is recomputed from the control block.

```python
spend = verify_spend(k1, note_url)   # opens which Q, at this mint? None if nothing
note_id_of(k1)                       # hex(Q): compare notes by this, never by k1
note_lookup_of(k1)                   # h or cp1, for note_info_by_hash_request
```

A key-path note's key comes from the seed, and its `ck1` needs the mint's
domain, which every call takes as a URL or a bare host and reduces to the
lowercase hostname (`spend_domain_of`):

```python
from lnurlcash_kit import (
    cash_node_to_cx1, derive_cash_address_node, derive_cash_root,
    derive_note_pubkey, derive_note_secret_key, encode_ck1, encode_cp1,
    encode_cx1, sign_note_ownership,
)

node = derive_cash_address_node(derive_cash_root(seed), "mint.example")
branch = cash_node_to_cx1(node)
watch_only = encode_cx1(branch.pubkey_x_only, branch.chain_code)

pk = derive_note_pubkey(branch.pubkey_x_only, branch.chain_code, i)  # Q, used as is
sk = derive_note_secret_key(node.private_key, node.chain_code, i)
ck1 = encode_ck1(sign_note_ownership(sk, "mint.example"))           # spends at mint.example only

client.rotate_note_with_hash(callback, ck1, encode_cp1(next_pk))     # sent as p1; its cs1 is owed
```

All-zero `aux_rand` makes a `ck1` a deterministic function of the key and the
domain, so seed recovery reproduces it byte for byte. `ck1`s signed before
spends moved onto the sighash (over `sha256("LNURLcash")`, over the raw
string, or the 65-byte recoverable ECDSA shape) are still read, and
`verify_spend` and `recover_note_ownership_pubkey` report them as `legacy`:
rotate those notes into a current `ck1`.

`encode_cw1`, `decode_cw1`, `output_key_of_cw1` and `bearer_cw1` handle
script-path spends; `key_path_sighash`, `script_path_sighash` and
`spend_sig_msg` give the hash a signer inside a leaf needs. There is no script
interpreter: a bearer hashlock is the one leaf this library evaluates, and any
other `cw1` is checked for structure, `Q` and LUD-25's leaf rules
(`check_leaf_policy`), then reported as `unevaluated`. The mint judges its
witness, and its time claim against its own clock (`check_time_claim`
predicts the answer).

A certificate, `cs1…`, carries the amount in its prefix by BOLT 11 amount
rules and signs `LNURLcash:<amount_msat>:<hex(Q)>`. A recipient checks a note
offline from its URL alone:

```python
amount, certified = verify_note_url(note_url, mint_pubkey)
# or piecewise:
certified = verify_note_signature(k1, note_url, amount_msat, cs1, mint_pubkey)
```

Both return a `Certification`: `CERTIFIED_OVER_Q`, as LUD-25 specifies;
`CERTIFIED_OVER_HASH` for a bearer note certified over its `h` by a mint from
before notes were keyed by `Q`; or `NOT_CERTIFIED`, the only falsy one.
`verify_note_signature` checks that `k1` opens its note at the URL's domain
first. `verify_note_signature_hash` takes a bearer note's `h` instead, and
`verify_note_signature_for_key` a `hex(Q)`, for a watcher that holds no
spend. A certificate proves issuance, not that the note is still outstanding:
rotate a received note once online.

`encode_cs1_with_amount`, `decode_cs1_with_amount` and `is_cs1_with_amount`
are the current wire API; the fixed-prefix `encode_cs1`, `decode_cs1` and
`is_cs1` remain for legacy certificates, and `decode_any_cs1` and
`is_any_cs1` accept either.

On the wire, a spend goes anywhere a `k1` does. An output, a `cp1` or a
bearer `h`, goes as `p1`/`p2` on a rotate, split or merge, as `p` on a lookup,
and as the comment on a mint invoice (a bearer `h` also as `h`, for mints that
took that parameter first). A `cp1` whose key is not a curve point is refused
before anything is sent.

Reference-mint address management proves control with the address branch's
index-0 key. `sign_address_proof(sk0, action, domain, username)` returns the
raw 64-byte BIP-340 proof over
`sha256("LNURLcash:<action>:<domain>:<username>")`; action is `register` or
`unregister`, the domain is the mint's own, and the username must be
normalised exactly as it is sent to the service.

Three things worth knowing:

- **The branch path is the spec's literal one.** It is `m/139'/d1/d2/d3/d4`,
  with the hashing key at `m/139'/0`: the same node `derive_cash_domain_node`
  returns. Wallets that derived under the earlier `m/139'/1'` hop hold notes
  this path does not find.
- **A `cx1` links every note on its branch.** It cannot spend anything, but
  whoever holds it can list every key on the branch and ask the mint about
  each one. Register it with a mint and that mint sees everything paid to the
  address. Use the branch for receiving and rotate off it.
- **Compare notes by `note_id_of`, never by the string.** `fetch_note_info`
  does: a mint that echoes another spend of the same note, valid at that
  mint, has named that note, and only a different note is refused.

**A branch rooted in a Nostr key.** This one is ours, not LUD-25's. A holder
with no BIP-39 words, such as a hardware signer that keeps only its identity
key, can still be paid to keys of its own. `derive_nostr_address_node(secret_key,
host)` takes the branch from the key behind the lightning address's npub:
`HMAC-SHA256(key = secret key, msg = "LNURLcash/nostr-seed")`, then the path
above unchanged. heartwood-esp32 derives the same branch on the device, so its
notes come back from the nsec without the device. A mint sees an ordinary
`cx1` either way.

Both are graded against lnurlcash-conformance's `vectors/part2.json` and
`vectors/nostr-seed.json`: every branch, key, signature, certificate and
string in them. The spends are graded against `vectors/spends.json`, and all
of it against `vectors/spec-vectors.json`, the numbers LUD-25's own text
publishes.

## Errors

| Class | Means |
| --- | --- |
| `RequestRefused` | nothing was sent. The note is untouched. |
| `ServiceRejected` | processed and refused. Definitive. |
| `NotePending` | a melt is in flight on this `k1`. Retry. |
| `NoteSpent` | authoritative: already burned. |
| `OutputInUse` | `already in use`: an output you named is taken. Nothing burned; name a fresh one. |
| `NoteUnknown` | the service does not recognise it. |
| `AmbiguousMint` | outcome **unknown**. Assume nothing. |
| `AmbiguousMutation` | as above, carrying `.new_secrets`. |
| `UnverifiableNote` | the mutation **landed** without a certificate it owed: for an output named by `cp1`, or by a bearer `h` under `require_signatures=True`. The note is real; carries `.new_secrets`. |
| `ProtocolError` | a non-mutating response did not match the spec, including a `withdrawRequest` with no `mintPubkey` (unless `require_mint_pubkey=False`). |

Branch on the class, never on the message.

`new_secrets_of(err)` reads the fresh secrets off any exception that could
describe a mutation the service applied: ambiguous, unverifiable, or a
spent-or-unknown refusal. A refusal on policy grounds burned nothing and
carries nothing.

## Scope

This library speaks the protocol. It does not store notes, hold keys, manage
a balance, pay invoices, or run a mint. Storage and key management are yours,
and they are where most of the remaining risk lives — see
[THREAT-MODEL.md](THREAT-MODEL.md).

Amounts are integers in **milli-satoshis**, everywhere, with no exceptions.

## Provenance

The reference implementations, both dni's, both MIT:

- [lnurl-mint](https://github.com/dni/lnurl-mint) — the reference service
- [lnurl-wallet](https://github.com/dni/lnurl-wallet) — the reference wallet

This library is a Python implementation of the same protocol, following that
wallet's protocol layer and checked against the same
[conformance vectors](https://github.com/lnurlcash/lnurlcash-conformance)
as its TypeScript, Rust and Go siblings — and against the same adversarial
mock mint, which can be told to drop a connection mid-mutation, sign in the
wrong byte order, lie about a note's value, or never settle a melt.

The wider ecosystem — wallets, mints, hardware and hosted services — is
indexed in [awesome-lnurlcash](https://github.com/lnurlcash/awesome-lnurlcash).

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
```

The suite needs `node` and a checkout of `lnurlcash-conformance` alongside
this repo (or `LNURLCASH_CONFORMANCE` pointing at one).

## License

MIT.
