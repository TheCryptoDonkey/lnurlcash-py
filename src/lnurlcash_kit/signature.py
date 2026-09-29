"""LUD-25 offline verification.

A SERVICE certifies each note it issues with its Lightning node identity key -
the same key it signs BOLT-11 invoices with - so a holder can confirm a note's
issuer and amount without contacting anyone. Signed via the node's own
signmessage RPC (lnd's /v1/signmessage, cln's signmessage), which wraps the
message with this prefix and double-SHA256s it before signing. That is
deliberate reuse: any tool that already verifies a Lightning node's signed
messages can verify a note, and neither backend can produce a bespoke
raw-digest scheme anyway.

    message = "LNURLcash:" || amount_msat (decimal ASCII) || ":" || hex(Q)
    digest  = sha256(sha256("Lightning Signed Message:" || message))

``Q`` is the note's output key, public for every note, a bearer note included:
the certificate names the note without disclosing anything that spends it. A
mint from before every note was keyed by ``Q`` certified a bearer note over
its ``h`` instead, and that message is still read, reported as such.
"""

from __future__ import annotations

from enum import Enum
from hashlib import sha256

from coincurve import PrivateKey, PublicKey

from .errors import ProtocolError
from .note import note_declared_amount, note_k1, note_signature
from .recoverable import (
    SpendKind,
    decode_any_cs1,
    decode_cs1_with_amount,
    decode_spend,
    note_id_of,
    verify_spend,
)
from .secrets import is_preimage
from .spend import bearer_hash_of_leaf, bearer_note_id, spend_domain_of

_LIGHTNING_SIGNED_MESSAGE_PREFIX = b"Lightning Signed Message:"
_DOMAIN_TAG = "LNURLcash"


def address_proof_message(action: str, domain: str, username: str) -> str:
    """The message that proves control of an address branch's index-0 key,
    bound to action, mint and username:
    ``LNURLcash:<action>:<domain>:<username>``. ``domain`` is the mint's own,
    in any form :func:`~lnurlcash_kit.spend.spend_domain_of` reads, and is
    written as its bare lowercase hostname. ``username`` must be the
    normalised value sent to the SERVICE."""
    if action not in ("register", "unregister"):
        raise ProtocolError("an address proof action is register or unregister")
    return f"{_DOMAIN_TAG}:{action}:{spend_domain_of(domain)}:{username}"


def address_proof_digest(action: str, domain: str, username: str) -> bytes:
    """:func:`address_proof_message`, hashed to the 32-byte digest that is
    actually signed: the message is variable-length, and most Schnorr signers
    only take 32 bytes."""
    return sha256(address_proof_message(action, domain, username).encode("utf-8")).digest()


def sign_address_proof(
    index_zero_secret_key: bytes, action: str, domain: str, username: str
) -> bytes:
    """Sign a register/update or unregister proof as a raw 64-byte BIP-340
    signature over :func:`address_proof_digest`, with 32 zero auxiliary bytes.
    Binding the domain stops a proof one mint has seen from being replayed at
    another.

    This is a fresh action a WALLET initiates itself, never a stored bearer
    secret read back later, so there is no old scheme to fall back to
    reading."""
    key = bytes(index_zero_secret_key)
    if len(key) != 32:
        raise ProtocolError("an index-zero secret key is 32 bytes")
    try:
        signer = PrivateKey(key)
    except ValueError as err:
        raise ProtocolError("an index-zero secret key is a scalar in [1, n)") from err
    return signer.sign_schnorr(address_proof_digest(action, domain, username), bytes(32))


def _require_note_id(k1: str) -> str:
    note_id = note_id_of(k1)
    if note_id is None:
        raise ProtocolError("a k1 is a ck1, a cw1, or a bearer note's 32-byte hex preimage")
    return note_id


def note_signature_message(k1: str, amount_msat: int) -> str:
    """The message a SERVICE certifies this note under, over ``hex(Q)`` of
    the note ``k1`` opens. Raises ``ProtocolError`` for anything that is no
    spend."""
    return note_signature_message_for_hash(_require_note_id(k1), amount_msat)


def note_signature_message_for_hash(h: str, amount_msat: int) -> str:
    """The same message for a caller holding a note's id as 32 bytes of hex
    rather than a spend of it: ``hex(Q)``, which is all a watcher holding only
    a cx1 has. Given a bearer note's ``h`` instead, it builds the message a
    mint from before taproot certified."""
    return f"{_DOMAIN_TAG}:{amount_msat}:{h.strip().lower()}"


def note_signature_digest(k1: str, amount_msat: int) -> bytes:
    return note_signature_digest_for_hash(_require_note_id(k1), amount_msat)


def note_signature_digest_for_hash(h: str, amount_msat: int) -> bytes:
    message = note_signature_message_for_hash(h, amount_msat).encode()
    return sha256(sha256(_LIGHTNING_SIGNED_MESSAGE_PREFIX + message).digest()).digest()


class Certification(Enum):
    """Whether a certificate verified, and over which message. Only
    ``NOT_CERTIFIED`` is falsy, so ``if verify_note_signature(...)`` reads as
    it always did."""

    #: the certificate does not verify for this note and amount
    NOT_CERTIFIED = "not certified"
    #: signed over ``hex(Q)``, as LUD-25 specifies
    CERTIFIED_OVER_Q = "certified over hex(Q)"
    #: a bearer note certified over its ``h``, the message a mint used before
    #: every note was keyed by ``Q``. Genuine, but from a mint that has not
    #: caught up
    CERTIFIED_OVER_HASH = "certified over the bearer note's h (pre-taproot)"

    @property
    def verified(self) -> bool:
        return self is not Certification.NOT_CERTIFIED

    def __bool__(self) -> bool:
        return self.verified


def verify_note_signature(
    k1: str, domain: str, amount_msat: int, signature_hex: str, mint_pubkey_hex: str
) -> Certification:
    """LUD-25's offline check of a note, as a recipient makes it: that ``k1``
    opens its note ``Q`` at ``domain`` (see
    :func:`~lnurlcash_kit.recoverable.verify_spend`), and that
    ``signature_hex`` certifies ``Q`` for ``amount_msat`` under
    ``mint_pubkey_hex``. A bearer note is tried over ``hex(Q)`` first, then
    over its ``h`` for a mint from before taproot.

    ``domain`` is the note URL's, in any form
    :func:`~lnurlcash_kit.spend.spend_domain_of` reads; a bearer note's spend
    opens it at any domain, but a ck1 only at the one it signed for. A cw1
    whose leaf this library cannot run is ``NOT_CERTIFIED`` here: only the
    mint can say whether it opens its note, so check the certificate alone
    with :func:`verify_note_signature_for_key` and leave the spend to the
    mint.

    ``signature_hex`` is 65 bytes of hex, an amount-bearing cs1, or a legacy
    fixed-prefix cs1. Which end of the 65 bytes carries the recovery id varies
    by implementation: LUD-25 calls for ``r || s || recovery_id``, the layout
    raw BOLT-11 signatures use, while lnurl-mint once forwarded its node's
    signmessage output unreordered as ``recovery_id || r || s``. Trying both
    costs nothing security-wise - recovering against the wrong one yields an
    unrelated key that cannot match - and means a note verifies regardless of
    which convention issued it.

    Never raises. Anything unverifiable is ``NOT_CERTIFIED``.
    """
    verified = verify_spend(k1, domain)
    if verified is None or verified.unevaluated:
        return Certification.NOT_CERTIFIED
    if _verify_certificate(verified.output_key.hex(), amount_msat, signature_hex, mint_pubkey_hex):
        return Certification.CERTIFIED_OVER_Q
    spend = decode_spend(k1)
    if spend is None or spend.kind is not SpendKind.SCRIPT_PATH or spend.script_path is None:
        return Certification.NOT_CERTIFIED
    h = bearer_hash_of_leaf(spend.script_path.script)
    if h is not None and _verify_certificate(h.hex(), amount_msat, signature_hex, mint_pubkey_hex):
        return Certification.CERTIFIED_OVER_HASH
    return Certification.NOT_CERTIFIED


def verify_note_signature_hash(
    h: str, amount_msat: int, signature_hex: str, mint_pubkey_hex: str
) -> Certification:
    """The certificate on a bearer note named by its hex ``h`` rather than a
    spend of it: a device that keeps the preimage to itself and discloses only
    ``h``, say. Over ``hex(Q)`` first, then over ``h`` itself for a mint from
    before taproot. Never raises."""
    try:
        q = bearer_note_id(h)
    except ProtocolError:
        return Certification.NOT_CERTIFIED
    if _verify_certificate(q, amount_msat, signature_hex, mint_pubkey_hex):
        return Certification.CERTIFIED_OVER_Q
    if _verify_certificate(h, amount_msat, signature_hex, mint_pubkey_hex):
        return Certification.CERTIFIED_OVER_HASH
    return Certification.NOT_CERTIFIED


def verify_note_signature_for_key(
    output_key_hex: str, amount_msat: int, signature_hex: str, mint_pubkey_hex: str
) -> Certification:
    """A certificate over a note's output key, given as ``hex(Q)``: a watcher
    checking a note minted to a key it derived from a cx1, or any note whose
    spend is not to hand. Never raises."""
    if _verify_certificate(output_key_hex, amount_msat, signature_hex, mint_pubkey_hex):
        return Certification.CERTIFIED_OVER_Q
    return Certification.NOT_CERTIFIED


def verify_note_url(note_url: str, mint_pubkey_hex: str) -> tuple[int | None, Certification]:
    """LUD-25's offline check on a note URL as a recipient holds it,
    ``lnurlw://mint.example/w?k1=<spend>&sig=<cs1>``: the spend from ``k1``,
    the domain from the URL's own host, and the amount from the cs1, or from
    the URL's ``amount`` when the certificate is an older one that carries
    none. Returns that amount with the verdict, the amount None when there was
    none to check. A certificate proves issuance, never that the note is still
    outstanding: rotate a received note once online. Never raises."""
    if not isinstance(note_url, str):
        return None, Certification.NOT_CERTIFIED
    k1, signature = note_k1(note_url), note_signature(note_url)
    try:
        domain = spend_domain_of(note_url)
    except ProtocolError:
        return None, Certification.NOT_CERTIFIED
    if not k1 or not signature:
        return None, Certification.NOT_CERTIFIED
    certificate = decode_cs1_with_amount(signature)
    amount = certificate.amount_msat if certificate is not None else note_declared_amount(note_url)
    if amount is None:
        return None, Certification.NOT_CERTIFIED
    return amount, verify_note_signature(k1, domain, amount, signature, mint_pubkey_hex)


def _verify_certificate(
    note_id: str, amount_msat: int, signature_hex: str, mint_pubkey_hex: str
) -> bool:
    """Recover the signer of a certificate over the note id and check it
    against ``mint_pubkey_hex``. Never raises."""
    if not isinstance(note_id, str) or not is_preimage(note_id):
        return False
    if not isinstance(signature_hex, str) or not isinstance(mint_pubkey_hex, str):
        return False
    signature = decode_any_cs1(signature_hex)
    if signature is None:
        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError:
            return False
    if len(signature) != 65:
        return False
    digest = note_signature_digest_for_hash(note_id, amount_msat)

    target = mint_pubkey_hex.strip().lower()
    # coincurve wants the recovery id last, which is also the wire format
    trailing = signature
    leading_moved = signature[1:] + signature[:1]
    for candidate in (trailing, leading_moved):
        try:
            recovered = PublicKey.from_signature_and_message(
                candidate, digest, hasher=None
            )
            if recovered.format(compressed=True).hex() == target:
                return True
        except Exception:
            # not a valid recovery under this ordering - try the other
            continue
    return False
