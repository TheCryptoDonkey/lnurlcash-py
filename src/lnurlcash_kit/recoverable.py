"""LUD-25's wire values, spends, and notes owned by a key.

Every note is a taproot output key ``Q``, written ``cp1<Q>`` (see
:mod:`lnurlcash_kit.spend`). A key-path note is the case where ``Q`` is the
holder's own key, used as is: the holder keeps ``sk``, discloses ``cp1<Q>``,
and spends the note with a ``ck1``, ``Q`` followed by a BIP-340 signature by
``sk`` over the key-path sighash for the mint's domain. The SERVICE certifies
every note with a ``cs1`` over ``hex(Q)``, so a recipient can check issuance
offline with nothing but the spend, the ``cs1`` and the note URL's domain.

:func:`decode_spend` and :func:`verify_spend` read any ``k1``: a ``ck1``, a
``cw1``, or a bearer note's hex preimage.

The names follow lnurl-wallet's ``src/lib``, in snake_case, and match
lnurlcash-go's. Graded against lnurlcash-conformance's ``spends.json``,
``part2.json`` and LUD-25's own published vectors.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256

from coincurve import PrivateKey, PublicKey, PublicKeyXOnly

from . import bech32
from .cash import CashNode, derive_cash_domain_node, derive_cash_root
from .errors import ProtocolError
from .secrets import hash_k1, is_preimage
from .spend import (
    KEY_PATH_LOCKTIME,
    KEY_PATH_SEQUENCE,
    Cw1,
    bearer_hash_of_leaf,
    bearer_note,
    check_leaf_policy,
    decode_cw1,
    is_x_only_point,
    key_path_sighash,
    output_key_of,
)

_CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ---- bech32m ----
#
# Each type has a fixed payload length, so there is no length limit to pick:
# ck1, cs1 and cx1 all exceed BIP-173's 90 characters, which the spec
# deliberately does not adopt. Mixed case is refused, as BIP-350 requires and
# lnurl-mint does; all-uppercase is the same string.


def _encode_fixed(hrp: str, payload: bytes, length: int) -> str:
    if len(payload) != length:
        raise ProtocolError(f"a {hrp}1 payload is {length} bytes, not {len(payload)}")
    return bech32.encode(hrp, bytes(payload), constant=bech32.BECH32M)


def _decode_fixed(hrp: str, value: str, length: int) -> bytes | None:
    if not isinstance(value, str):
        return None
    decoded = bech32.decode(value.strip(), constant=bech32.BECH32M)
    if decoded is None:
        return None
    prefix, payload = decoded
    if prefix != hrp or len(payload) != length:
        return None
    return payload


def encode_cp1(pubkey_x_only: bytes) -> str:
    """A note's output key ``Q``: 32-byte x-only, as BIP-340 writes it."""
    return _encode_fixed("cp", pubkey_x_only, 32)


def decode_cp1(value: str) -> bytes | None:
    """A ``cp1``'s key, or None. A ``Q`` that is not the x coordinate of a
    curve point is refused, as LUD-25 has a SERVICE refuse it: no spend could
    ever open that note, so paying into it would burn the money."""
    key = _decode_fixed("cp", value, 32)
    return key if key is not None and is_x_only_point(key) else None


def is_cp1(value: str) -> bool:
    return decode_cp1(value) is not None


def encode_ck1(payload: bytes) -> str:
    """A key-path spend: the note's 32-byte output key ``Q`` followed by its
    64-byte BIP-340 signature, from :func:`sign_note_ownership`. Whoever holds
    this string holds the note, at the one mint it was signed for."""
    return _encode_fixed("ck", payload, 96)


def decode_ck1(value: str) -> bytes | None:
    """The payload inside a ``ck1``: 96 bytes for the ``Q || sig`` form, or 65
    bytes for a pre-Schnorr recoverable-ECDSA bearer, accepted only so
    existing notes remain spendable long enough to rotate into the current
    format. The length says which. :func:`encode_ck1` only takes the 96-byte
    form."""
    current = _decode_fixed("ck", value, 96)
    return current if current is not None else _decode_fixed("ck", value, 65)


def is_ck1(value: str) -> bool:
    return decode_ck1(value) is not None


def encode_cs1(signature: bytes) -> str:
    """A legacy fixed-prefix certificate, retained for old notes and callers.

    New code should use :func:`encode_cs1_with_amount`.
    """
    return _encode_fixed("cs", signature, 65)


def decode_cs1(value: str) -> bytes | None:
    return _decode_fixed("cs", value, 65)


def is_cs1(value: str) -> bool:
    return decode_cs1(value) is not None


@dataclass(frozen=True)
class Cs1:
    """A current amount-bearing mint certificate."""

    amount_msat: int
    signature: bytes


def _encode_cs1_amount_suffix(amount_msat: int) -> str:
    for suffix, unit in (
        ("", 100_000_000_000),
        ("m", 100_000_000),
        ("u", 100_000),
        ("n", 100),
    ):
        if amount_msat % unit == 0:
            return f"{amount_msat // unit}{suffix}"
    # One pico-BTC is 0.1 msat. Every whole msat is exactly ten pico-BTC.
    return f"{amount_msat * 10}p"


def _decode_cs1_amount_suffix(value: str) -> int | None:
    if not value:
        return None
    unit = value[-1] if value[-1] in "munp" else ""
    digits = value[:-1] if unit else value
    if not digits or not digits.isascii() or not digits.isdigit():
        return None
    number = int(digits)
    if unit == "":
        return number * 100_000_000_000
    if unit == "m":
        return number * 100_000_000
    if unit == "u":
        return number * 100_000
    if unit == "n":
        return number * 100
    if number % 10:
        return None
    return number // 10


def encode_cs1_with_amount(amount_msat: int, signature: bytes) -> str:
    """Encode a current certificate whose prefix carries ``amount_msat``
    using BOLT 11 amount suffix rules.

    The payload is the mint's recoverable signature over that same amount and
    the note key. Encoding does not sign or verify it.
    """
    if isinstance(amount_msat, bool) or not isinstance(amount_msat, int) or amount_msat < 0:
        raise ProtocolError("amount_msat must be a non-negative integer")
    return _encode_fixed("cs" + _encode_cs1_amount_suffix(amount_msat), signature, 65)


def decode_cs1_with_amount(value: str) -> Cs1 | None:
    """Decode a current certificate and the amount carried by its prefix.

    The legacy fixed ``cs`` prefix returns ``None`` because it carries no
    amount.
    """
    if not isinstance(value, str):
        return None
    decoded = bech32.decode(value.strip(), constant=bech32.BECH32M)
    if decoded is None:
        return None
    prefix, payload = decoded
    if not prefix.startswith("cs") or len(payload) != 65:
        return None
    amount_msat = _decode_cs1_amount_suffix(prefix[2:])
    if amount_msat is None:
        return None
    return Cs1(amount_msat, payload)


def is_cs1_with_amount(value: str) -> bool:
    return decode_cs1_with_amount(value) is not None


def decode_any_cs1(value: str) -> bytes | None:
    """Return the signature from either a current or legacy certificate."""
    current = decode_cs1_with_amount(value)
    return current.signature if current is not None else decode_cs1(value)


def is_any_cs1(value: str) -> bool:
    return decode_any_cs1(value) is not None


@dataclass(frozen=True)
class Cx1:
    """A watch-only branch: its x-only public key and chain code.

    Anyone holding one can list every note key on the branch, and link them,
    but cannot spend any. Not secret the way a :class:`CashNode` is, but not
    something to publish either.
    """

    pubkey_x_only: bytes
    chain_code: bytes


def encode_cx1(pubkey_x_only: bytes, chain_code: bytes) -> str:
    if len(pubkey_x_only) != 32 or len(chain_code) != 32:
        raise ProtocolError(
            "a cx1 is a 32-byte x-only public key and a 32-byte chain code"
        )
    return _encode_fixed("cx", bytes(pubkey_x_only) + bytes(chain_code), 64)


def decode_cx1(value: str) -> Cx1 | None:
    payload = _decode_fixed("cx", value, 64)
    return Cx1(payload[:32], payload[32:]) if payload is not None else None


def is_cx1(value: str) -> bool:
    return decode_cx1(value) is not None


# ---- the per-note key tweak ----
#
#     t    = tagged_hash("LNURLcash/derive", P || chainCode || ser32_be(i))
#     pk_i = x(lift_x(P) + t*G)
#     sk_i = ((P has even y ? p : n - p) + t) mod n
#
# BIP-341's taproot tweak, so a watcher holding only the cx1 computes the same
# pk_i the holder does. i is any uint32 and is never hardened. The 4-byte
# big-endian width is what lnurl-wallet and lnurl-mint both use; the spec text
# does not pin it.

_NOTE_DERIVE_TAG = sha256(b"LNURLcash/derive").digest()


def _unusable(index: int) -> ProtocolError:
    return ProtocolError(
        f"note index {index} is unusable on this branch - use the next index"
    )


def _require_uint32(index: int) -> int:
    # bool is an int to Python, and True is not an index anyone meant
    if isinstance(index, bool) or not isinstance(index, int):
        raise ProtocolError(f"a note index must be a uint32, not {index!r}")
    if not 0 <= index <= 0xFFFFFFFF:
        raise ProtocolError(f"a note index must be a uint32, not {index}")
    return index


def _tweak_for(pubkey_x_only: bytes, chain_code: bytes, index: int) -> int:
    if len(pubkey_x_only) != 32 or len(chain_code) != 32:
        raise ProtocolError(
            "a branch is a 32-byte x-only public key and a 32-byte chain code"
        )
    ser = _require_uint32(index).to_bytes(4, "big")
    material = _NOTE_DERIVE_TAG + _NOTE_DERIVE_TAG + pubkey_x_only + chain_code + ser
    # reduced mod n, as the spec requires and lnurl-wallet does (lnurl-mint
    # refuses t >= n instead; at ~2^-128 the two never meet)
    return int.from_bytes(sha256(material).digest(), "big") % _CURVE_N


def derive_note_pubkey(
    branch_pubkey_x_only: bytes, chain_code: bytes, index: int
) -> bytes:
    """The i-th note's x-only public key, from the branch's public half alone.

    Watch-only: it needs no private key, which is what lets a SERVICE holding
    a registered cx1 mint straight to the holder's next key.
    """
    branch_x = bytes(branch_pubkey_x_only)
    t = _tweak_for(branch_x, bytes(chain_code), index)
    try:
        branch = PublicKey(b"\x02" + branch_x)
    except ValueError as err:
        raise ProtocolError("that branch key is not a point on secp256k1") from err
    if t == 0:
        return branch_x
    try:
        # P + t*G. coincurve refuses the point at infinity, the one other way
        # an index can be unusable
        note = branch.add(t.to_bytes(32, "big"))
    except ValueError as err:
        raise _unusable(index) from err
    return note.format(compressed=True)[1:]


def derive_note_secret_key(
    branch_private_key: bytes, chain_code: bytes, index: int
) -> bytes:
    """The holder's half: the i-th note's 32-byte secret key.

    The branch key's own point may have odd y, and a cx1 carries only x, which
    names the even-y point, so the key is negated first. Without that the note
    keys would not match what a watcher derives from the cx1.
    """
    key = bytes(branch_private_key)
    p = int.from_bytes(key, "big")
    if len(key) != 32 or not 0 < p < _CURVE_N:
        raise ProtocolError("a branch private key is a 32-byte scalar in [1, n)")
    branch = PrivateKey(key).public_key.format(compressed=True)
    t = _tweak_for(branch[1:], bytes(chain_code), index)
    even = p if branch[0] == 0x02 else _CURVE_N - p
    note = (even + t) % _CURVE_N
    if note == 0:
        raise _unusable(index)
    return note.to_bytes(32, "big")


# ---- key-path spends ----
#
#     sig = BIP340.Sign(sk, key_path_sighash(Q, domain), aux_rand = 0^32)
#     ck1 = bech32m("ck", Q || sig)
#
# The sighash depends on nothing but the note and the mint, and the auxiliary
# input is fixed, so a key has exactly one ck1 per mint: re-deriving the key
# reproduces it byte for byte, which is what lets seed recovery find a note
# already held. A ck1 for one mint fails at every other.
#
# Two older ck1s are still read, never made, so notes already handed out stay
# spendable long enough to rotate: the same Q || sig shape signed over the
# fixed message sha256("LNURLcash") (and, before 2026-09-16, the raw 9-byte
# string), and the pre-Schnorr 65-byte recoverable ECDSA signature.

_NOTE_OWNERSHIP_MESSAGE = b"LNURLcash"
_NOTE_OWNERSHIP_DIGEST = sha256(_NOTE_OWNERSHIP_MESSAGE).digest()
_ZERO_AUX = bytes(32)
_LIGHTNING_SIGNED_MESSAGE_PREFIX = b"Lightning Signed Message:"
_LEGACY_NOTE_OWNERSHIP_DIGEST = sha256(
    sha256(_LIGHTNING_SIGNED_MESSAGE_PREFIX + _NOTE_OWNERSHIP_MESSAGE).digest()
).digest()
# BIP-342 keeps the 520-byte cap on every initial stack element.
_MAX_STACK_ELEMENT = 520


def sign_note_ownership(secret_key: bytes, domain: str) -> bytes:
    """A key-path note's spend at one mint: the 96-byte ``Q || sig`` payload.
    Encode with :func:`encode_ck1` for the wire: that string spends the note,
    so it is as secret as the key. ``domain`` is the mint's, in any form
    :func:`~lnurlcash_kit.spend.spend_domain_of` reads.

    ``sig`` is BIP-340 over the key-path sighash with 32 zero auxiliary
    bytes, so a wallet restored from its seed reproduces every ck1 exactly.
    """
    key = bytes(secret_key)
    # checked here because coincurve zero-pads a short key rather than
    # refusing it, and a short key is somebody's bug
    if len(key) != 32:
        raise ProtocolError("a note secret key is 32 bytes")
    try:
        signer = PrivateKey(key)
    except ValueError as err:
        raise ProtocolError("a note secret key is a scalar in [1, n)") from err
    q = signer.public_key_xonly.format()
    return q + signer.sign_schnorr(key_path_sighash(q, domain), _ZERO_AUX)


@dataclass(frozen=True)
class NoteOwnership:
    """The note a verified ``ck1`` opens."""

    pubkey_x_only: bytes
    #: a ck1 signed over a fixed message rather than the spend sighash, or the
    #: pre-Schnorr recoverable shape. Rotate it.
    legacy: bool = False


def _recover_legacy_ck1(payload: bytes) -> bytes | None:
    """The key behind a pre-Schnorr 65-byte ck1, an ``r || s || recovery id``
    signature over a fixed message. Recovering a key is that shape's whole
    check: it names its note by the key it recovers to."""
    try:
        recovered = PublicKey.from_signature_and_message(
            bytes(payload), _LEGACY_NOTE_OWNERSHIP_DIGEST, hasher=None
        )
    except Exception:
        # a recovery id above 3, r or s out of range, or no point at all
        return None
    return recovered.format(compressed=True)[1:]


def recover_note_ownership_pubkey(payload: bytes, domain: str) -> NoteOwnership | None:
    """Verify a ck1's payload and return the note it opens, or None. Never
    raises.

    A 96-byte ``Q || sig`` is verified against the key-path sighash for
    ``domain`` first; failing that, against the fixed messages older ck1s
    signed, which reports ``legacy``. A 65-byte recoverable signature is
    recovered, and is always ``legacy``. :func:`sign_note_ownership` only
    ever makes the first.
    """
    if not isinstance(payload, (bytes, bytearray)):
        return None
    payload = bytes(payload)
    if len(payload) == 96:
        try:
            key = PublicKeyXOnly(payload[:32])
        except Exception:
            # a key that is not on the curve
            return None
        signature = payload[32:]

        def verifies(message: bytes) -> bool:
            try:
                return bool(key.verify(signature, message))
            except Exception:
                return False

        # A missing or unreadable domain only rules out the current form: the
        # fixed-message ones never had one.
        try:
            sighash: bytes | None = key_path_sighash(payload[:32], domain)
        except ProtocolError:
            sighash = None
        if sighash is not None and verifies(sighash):
            return NoteOwnership(payload[:32])
        if verifies(_NOTE_OWNERSHIP_DIGEST) or verifies(_NOTE_OWNERSHIP_MESSAGE):
            return NoteOwnership(payload[:32], legacy=True)
        return None
    if len(payload) != 65:
        return None
    recovered = _recover_legacy_ck1(payload)
    return NoteOwnership(recovered, legacy=True) if recovered is not None else None


# ---- spends ----


class SpendKind(Enum):
    """How a spend opens its note."""

    #: a ck1: Q and a BIP-340 signature
    KEY_PATH = "key path"
    #: a cw1, or a bearer note's hex preimage, its short form
    SCRIPT_PATH = "script path"
    #: a pre-Schnorr 65-byte ck1, whose key is recovered rather than read.
    #: Deprecated, and only ever read
    RECOVERED_KEY = "recovered key"


@dataclass(frozen=True)
class Spend:
    """What a ``k1`` decodes to: the note it names and how it opens it."""

    kind: SpendKind
    output_key: bytes
    #: a key-path spend's BIP-340 signature
    signature: bytes | None = None
    #: a script-path spend's leaf, control block and witness. A bearer
    #: preimage decodes to its full cw1
    script_path: Cw1 | None = field(default=None)


def decode_spend(k1: str) -> Spend | None:
    """Read what a redeemer put in ``k1`` and name the note it opens, or None
    for anything that is no spend. Nothing here checks a signature or a
    witness: for that, :func:`verify_spend`. Never raises."""
    if not isinstance(k1, str):
        return None
    value = k1.strip()
    if is_preimage(value):
        secret = bytes.fromhex(value)
        note = bearer_note(sha256(secret).digest())
        return Spend(
            SpendKind.SCRIPT_PATH,
            note.output_key,
            script_path=Cw1(
                KEY_PATH_LOCKTIME, KEY_PATH_SEQUENCE, note.leaf, note.control_block, (secret,)
            ),
        )
    payload = decode_ck1(value)
    if payload is not None:
        if len(payload) == 65:
            key = _recover_legacy_ck1(payload)
            return Spend(SpendKind.RECOVERED_KEY, key) if key is not None else None
        return Spend(SpendKind.KEY_PATH, payload[:32], signature=payload[32:])
    script = decode_cw1(value)
    if script is None:
        return None
    q = output_key_of(script.script, script.control_block)
    return Spend(SpendKind.SCRIPT_PATH, q, script_path=script) if q is not None else None


@dataclass(frozen=True)
class VerifiedSpend:
    """A spend that opens its note, as far as this library can judge without
    the mint's clock."""

    output_key: bytes
    #: a ck1 signed under a scheme LUD-25 has replaced: over a fixed message
    #: rather than the spend sighash, or the pre-Schnorr recoverable shape.
    #: Still read, so notes already handed out stay spendable; rotate it into
    #: a current ck1 at the first chance
    legacy: bool = False
    #: a script-path spend whose leaf is not a bearer hashlock, the one leaf
    #: this library runs. Its structure, its Q and the leaf rules were
    #: checked; whether its witness satisfies the leaf is the mint's call
    unevaluated: bool = False


def verify_spend(k1: str, domain: str) -> VerifiedSpend | None:
    """Check that ``k1`` opens the note it names, the way a mint would (LUD-25
    "Output keys and spends"), leaving only its time claims to the mint's
    clock. None when it does not. Never raises.

    ``domain`` is the mint's, in any form
    :func:`~lnurlcash_kit.spend.spend_domain_of` reads: a key-path signature
    is bound to it. A bearer note's spend checks no signature, so it opens its
    note at any domain.
    """
    spend = decode_spend(k1)
    if spend is None:
        return None
    if spend.kind is SpendKind.RECOVERED_KEY:
        return VerifiedSpend(spend.output_key, legacy=True)
    if spend.kind is SpendKind.KEY_PATH:
        owner = recover_note_ownership_pubkey(spend.output_key + (spend.signature or b""), domain)
        return VerifiedSpend(owner.pubkey_x_only, legacy=owner.legacy) if owner else None
    script = spend.script_path
    assert script is not None
    if check_leaf_policy(script.control_block[0] & 0xFE, script.script) is not None:
        return None
    h = bearer_hash_of_leaf(script.script)
    if h is None:
        return VerifiedSpend(spend.output_key, unevaluated=True)
    # OP_SHA256 <h> OP_EQUAL leaves exactly one element, true only for a lone
    # witness item under the stack-element cap that hashes to h. That is the
    # whole of what Bitcoin Core would decide about this leaf.
    witness = script.witness
    if len(witness) != 1 or len(witness[0]) > _MAX_STACK_ELEMENT:
        return None
    if sha256(witness[0]).digest() != h:
        return None
    return VerifiedSpend(spend.output_key)


# ---- a note's k1, any kind ----


def note_id_of(k1: str) -> str | None:
    """The id a SERVICE files the note ``k1`` opens under: ``hex(Q)``. A
    bearer preimage names the bearer note it opens, a cw1 the ``Q`` its
    control block commits to, a ck1 the ``Q`` it carries. None for anything
    that is no spend.

    This names the note; it does not check that ``k1`` opens it, which for a
    ck1 needs the mint's domain. That is :func:`verify_spend`.
    """
    if not isinstance(k1, str):
        return None
    spend = decode_spend(k1.strip().lower())
    return spend.output_key.hex() if spend is not None else None


def note_lookup_of(k1: str) -> str | None:
    """What to look a note up by without disclosing it: a bearer preimage's
    hex ``h``, which every mint that ever took a hash lookup understands, and
    the cp1 of anything else. Both are LUD-25's cp1 slot, and both bring the
    note's certificate back. Pass it to
    :func:`~lnurlcash_kit.protocol.note_info_by_hash_request`."""
    if not isinstance(k1, str):
        return None
    value = k1.strip().lower()
    if is_preimage(value):
        return hash_k1(value)
    spend = decode_spend(value)
    return encode_cp1(spend.output_key) if spend is not None else None


# ---- the address branch ----


def derive_cash_address_node(root: CashNode, host: str) -> CashNode:
    """``m/139'/d1/d2/d3/d4`` for one mint - the literal path LUD-25's text
    specifies, and the exact node
    :func:`~lnurlcash_kit.cash.derive_cash_domain_node` already derives for any
    SERVICE. There is no separate purpose for key-path notes: an earlier
    reference-wallet extension deterministically derived bearer preimages off
    this same root too, under a ``1'`` sub-purpose kept just for this branch to
    avoid colliding with it; that extension is gone (see
    :mod:`~lnurlcash_kit.cash`), so there is nothing left to collide with.

    Bearer material for every note on the branch. Hand out
    :func:`cash_node_to_cx1` of it, never the node.
    """
    return derive_cash_domain_node(root, host)


def cash_node_to_cx1(node: CashNode) -> Cx1:
    """A node's watch-only half: what :func:`encode_cx1` encodes."""
    try:
        point = PrivateKey(node.private_key).public_key.format(compressed=True)
    except ValueError as err:
        raise ProtocolError("cash node holds an invalid private key") from err
    return Cx1(point[1:], bytes(node.chain_code))


# ---- a branch rooted in a Nostr key ----
#
# An extension, not LUD-25. A lightning address on a Nostr-native mint belongs
# to an npub, and a holder with no BIP-39 words - a hardware signer that keeps
# only its identity key, or a wallet that never made any - can still be paid to
# keys of its own:
#
#     seed = HMAC-SHA256(key = the identity's secret key, msg = "LNURLcash/nostr-seed")
#
# then the address path from that seed, unchanged. heartwood-esp32
# derives exactly this on the device, and lnurlcash-conformance's
# vectors/nostr-seed.json holds both to it. The identity key rebuilds every
# note paid to the branch, so whoever can restore that key can recover the
# notes, with or without the device that received them. A mint sees an
# ordinary cx1 either way.

NOSTR_CASH_SEED_LABEL = "LNURLcash/nostr-seed"


def derive_nostr_cash_seed(secret_key: bytes) -> bytes:
    """The 32-byte seed a Nostr identity's branch grows from. ``secret_key``
    is the raw 32 bytes an nsec encodes."""
    if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) != 32:
        raise ProtocolError("a Nostr secret key is 32 bytes")
    return hmac.new(
        bytes(secret_key), NOSTR_CASH_SEED_LABEL.encode("utf-8"), sha256
    ).digest()


def derive_nostr_address_node(secret_key: bytes, host: str) -> CashNode:
    """One mint's address branch for a Nostr identity. Bearer material, like
    any address node: hand out :func:`cash_node_to_cx1` of it."""
    return derive_cash_address_node(
        derive_cash_root(derive_nostr_cash_seed(secret_key)), host
    )
