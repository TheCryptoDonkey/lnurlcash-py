# Threat model

What this library defends against, what it cannot, and what it hands to you.

## What it is

A protocol client for LNURLcash bearer notes. It builds requests, classifies
responses, generates replacement note secrets, and verifies mint signatures
offline. It holds no state between calls.

## Assets

**Spends (`k1`).** Every note is a taproot output key `Q`, and a spend opens
it: a bearer note's preimage (or its full `cw1`), a `ck1` signed by a note
key, or a `cw1` satisfying some other leaf. Bearer instruments: whoever holds
one can spend it, with no further authentication. A bearer preimage works at
any mint that holds its note; a `ck1` only at the mint whose domain it
signed. Compromise is theft, and it is silent and irreversible: the money is
gone before the previous holder has any way to notice.

**Note keys and address branches.** A note key signs its `ck1`, so it is the
note. An address node derives every note key on its branch.

**Replacement secrets awaiting confirmation.** After a mutation whose outcome
is unknown, the secrets generated in-process may be the only copies of notes
a service has already minted. Losing them destroys the money exactly as
thoroughly as leaking them gives it away.

**Mint pubkeys.** Not secret, but a wrong one makes offline verification
meaningless.

## Trust boundaries

| Party | Trusted for |
| --- | --- |
| the SERVICE (mint) | custody of the sats, and honest accounting. Nothing else. |
| the caller's storage | confidentiality and durability of secrets. This library provides neither. |
| the caller's RNG | unpredictability of replacement secrets. Substitutable, and load-bearing. |
| the network | nothing. |

A mint is trusted with custody by construction — it holds the funds. It is
*not* trusted to describe them accurately, which is why value comes from
`maxWithdrawable` rather than from a note URL's own `amount`, and why a
signed note can be checked against a key the mint published earlier.

## What this library defends against

**A service that keeps a copy of your note.** Rotate, split and merge disclose
only a public name for each output: a `cp1`, or a bearer note's
`h = sha256(preimage)`, from which the service computes the note's `Q`. It
files the note under `hex(Q)` and never sees what spends it. This is the
difference between a bearer note and a receipt, and it is why a
service-generated replacement is refused even when offered
(`serverGeneratedSecrets` in the mock mint exercises exactly this).

**A spend replayed at another mint.** A `ck1` signs the key-path sighash of a
canonical transaction whose prevout is `tagged_hash("LNURLcash/mint",
domain)`, so a signature one mint has seen verifies nowhere else.
`sign_note_ownership` takes the domain from whatever URL or host it is given
and keeps only the lowercase hostname, so a scheme, a port or a case
difference cannot silently sign for a mint that does not exist. A register
or unregister proof binds the domain the same way. A bearer note's spend
signs nothing and is bound to no mint: it spends its note wherever the note
exists, exactly as a plain `k1` always has.

**A spend that does not open its note.** `verify_spend` checks a spend the
way a mint does: a `ck1`'s signature for the domain, a `cw1`'s control block
(merkle path, tweak and parity) against `Q`, the leaf rules, and a bearer
leaf's hashlock. `resolve_note_input` and the informational GET's echo check
use it, so a `ck1` for another mint, or one with the right key and a broken
signature, is not taken for the note.

**An upgrade-hook leaf.** A leaf version other than `0xc0`, or an
`OP_SUCCESSx` opcode outside pushed data, succeeds unconditionally under
consensus today, so anyone who saw such a leaf could spend it. Both are
refused (`check_leaf_policy`), as LUD-25 has a mint refuse them.

**A cp1 nobody could spend.** A `cp1` whose key is not a curve point is
refused on decode, so a mint invoice to one is never requested and never
paid.

**A mutation whose outcome is unknown.** Timeouts, dropped connections,
unreadable bodies and unconfirmed 200s are all raised as
`AmbiguousMutationError` carrying the fresh secrets, never as failure.
Requests that provably never left — offline mode, a refused URL, an
unparseable callback — are raised as `RequestRefusedError` instead, which is
safe to treat as "nothing happened".

**A note that answers its own questions.** Every URL fetched, whether scanned
by a user or supplied by a service in its own response, must be https, or
http to loopback or `.onion`. A `data:` URL carrying withdrawRequest JSON
would otherwise mint a self-contained fake note that verifies against
nothing.

**A service that inflates a note.** A certificate (`cs1`) commits to the
amount and to the note's `hex(Q)`, for every note, a bearer note included. A
service reporting more than it signed fails verification, without the holder
contacting anyone. This library always demands a certificate for an output
named by `cp1`; the tolerant default admits an uncertified output named by a
bearer `h` from a mint with no signer, and that particular note has no offline
amount check. A certificate over a bearer note's `h`, the message mints used
before notes were keyed by `Q`, is still read and reported as
`CERTIFIED_OVER_HASH`, so a caller can tell a mint that has not caught up.

**A service that swaps your note.** The informational GET checks that the
echoed `k1` is the one queried, or another spend that opens the same `Q` at
that mint. Anything else means either a non-compliant service or a note
redeemed by somebody else.

**A secret leaking through a query string.** `sig` is stripped before the
informational GET, since the service already knows what it signed.

**A hostile fee advertisement.** Fees of 100% or more are refused at parse
time, and the gross-up search is a binary search rather than a walk — so a
service cannot stall a caller with an extreme fee.

**Integer overflow on realistic amounts.** Python integers are arbitrary
precision, so this cannot bite here - but the proportional fee term is still
computed split, exactly as the Rust and Go ports must compute it, so that a
disagreement between languages is a difference in inputs rather than a
difference in arithmetic.

## What it does not defend against

**Storage compromise.** This library never persists anything. If your
storage is readable — an unencrypted database, a synced folder, a debugger,
a crash dump — every note in it is spendable by whoever reads it. Encrypt at
rest, and treat backups as the same exposure.

**A weak RNG.** `rng` is replaceable, which means it can be replaced
badly. A predictable secret is a note anyone can mint themselves. Use the
platform CSPRNG, or a hardware RNG, and nothing else.

**Secrets in logs.** A note URL carries its secret in a query string. A
request logger, an error reporter, a crash handler or an analytics SDK that
records URLs records bearer money. This library never logs; what wraps it
might.

**A malicious or compromised mint.** It holds the funds. It can refuse to
honour a note, vanish, or inflate its liabilities. Offline verification
proves what it *said*, which is useful for exposing it afterwards, and is
not custody.

**The mint-time preimage race.** A freshly minted note's secret is the
invoice preimage, so the service has necessarily seen it, and anyone who saw
the unpaid invoice can poll LUD-21 `verify` for it the moment it settles.
Rotating immediately wins that race; a slow manual flow does not. Do not
publish unpaid mint invoices.

**Traffic analysis.** Every operation reaches the mint directly. The mint
learns your IP, your timing, and which notes move together. Notes are bearer
instruments, not private ones — merging several notes tells the mint they
had one holder. Route over Tor if that matters.

**Anything about the sats themselves.** No custody, no channel management,
no payment routing.

**Leaves this library cannot run.** There is no script interpreter here. A
`cw1` whose leaf is not a bearer hashlock is checked for structure, `Q` and
the leaf rules only, and `verify_spend` says so (`unevaluated`);
`verify_note_signature` refuses to vouch for one. Only the mint, running
consensus rules, decides whether its witness satisfies the leaf.

**Timelocks.** A timelock a mint honours is the mint asserting its own clock:
a custodial policy, never a trustless guarantee. `check_time_claim` only
predicts what an honest mint's clock will say.

## The retry hazard

Every LNURLcash mutation is an HTTP GET, and HTTP treats GET as idempotent, so
a stack may resend one when a connection fails mid-flight. An LNURLcash
mutation is not idempotent: the first attempt burns the input.

A retried mutation is therefore answered "already spent", which classifies as a
definitive rejection — so a caller concludes nothing happened and discards the
fresh secret that was the only copy of the note the service just minted.

`httpx` does not retry by default, and this library adds none. A caller passing
its own client must not configure a retrying transport, and must exclude these
requests from any retry decorator or resilience layer.

The hazard is real rather than theoretical — it broke the Kotlin and Go
siblings during development, by two different mechanisms — and is a named
scenario in the conformance vectors.

## Deliberate design choices

**Both signature recovery-id orderings are accepted.** The wire format is
`r || s || recovery_id`; lnurl-mint once emitted the reverse. Trying both is
not a weakening: recovering under the wrong ordering yields an unrelated
pubkey, which cannot match the expected one.

**Errors are typed by whether the request could have been processed**, not by
transport detail. That distinction is the whole safety model, and message
text is not a stable interface — never branch on it.

**No global state.** Offline mode, timeout, HTTP client and RNG are constructor parameters. A
caller that wants certainty nothing reaches the network sets `offline` and
gets a refusal, rather than trusting that no code path happens to make a
request.

## Reporting

See [SECURITY.md](SECURITY.md).
