"""LUD-25 spends: what a note is, and what a signature signs.

Every note is a BIP-341 taproot output key ``Q``, named ``cp1<Q>``, and a mint
files it under ``hex(Q)``. What goes in ``k1`` is a spend of one::

    ck1<Q || sig>   key path: a BIP-340 signature by Q itself
    cw1<...>        script path: a leaf of Q's tree, its control block and
                    the witness the leaf consumes
    64 hex          a bearer note's preimage, the short form of its cw1

Every signature signs the BIP-341 sighash of input 0 of one fixed,
never-broadcast transaction whose prevout is bound to the mint's domain, so a
signature one mint has seen cannot be replayed at another::

    nVersion 2, nLockTime as claimed
    vin[0]   prevout (tagged_hash("LNURLcash/mint", domain), 0), nSequence as claimed
    vout[0]  value 0, empty scriptPubKey
    spent    (OP_1 <Q>, 0)

The shape of that transaction never changes, so the sighash is built here by
hand rather than through a Bitcoin library. There is no script interpreter
either: a bearer note's hashlock is the one leaf this library evaluates (see
:func:`~lnurlcash_kit.recoverable.verify_spend`), and any other leaf is only
checked as far as its structure, its ``Q`` and the leaf rules go. Nothing
here is secret, so none of it needs to be constant-time.

Decoding a spend lives in :mod:`lnurlcash_kit.recoverable`, beside the
``ck1`` it has to read.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import urlparse

from coincurve import PublicKey

from . import bech32
from .errors import ProtocolError
from .secrets import is_preimage
from .urls import from_bech32_lnurl, from_lud17, is_bech32_lnurl

#: Tapscript's leaf version, the only one LUD-25 accepts.
TAPLEAF_VERSION = 0xC0
#: The time claim every key-path spend makes: none. A key therefore has one
#: signature per mint.
KEY_PATH_LOCKTIME = 0
KEY_PATH_SEQUENCE = 0xFFFFFFFF

#: BIP-341's nothing-up-my-sleeve point H. Nobody knows its discrete log, so a
#: note built on it has no key path: only its leaf can spend it.
NUMS_KEY = bytes.fromhex(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)

_CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_MAX_MERKLE_DEPTH = 128
# no URL gets near this; it only stops a hostile string costing work
_MAX_CW1_CHARS = 8192
# a cw1 names each item's length in two bytes
_MAX_CW1_ITEM = 0xFFFF


def _tagged_hash(tag: str, *parts: bytes) -> bytes:
    tag_hash = sha256(tag.encode()).digest()
    return sha256(tag_hash + tag_hash + b"".join(parts)).digest()


def _compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def _lift_x(x: bytes) -> PublicKey | None:
    """BIP-340's lift_x: the even-y point with this x, or None when ``x`` is
    not the x coordinate of any point on the curve."""
    if not isinstance(x, (bytes, bytearray)) or len(x) != 32:
        return None
    try:
        return PublicKey(b"\x02" + bytes(x))
    except ValueError:
        return None


def is_x_only_point(x: bytes) -> bool:
    """Whether ``x`` is the x coordinate of a curve point. LUD-25 has a mint
    refuse a ``cp1`` that is not: no spend could ever open it."""
    return _lift_x(x) is not None


def tap_leaf_hash(script: bytes, version: int = TAPLEAF_VERSION) -> bytes:
    """BIP-341's ``tagged_hash("TapLeaf", version || compact_size(len) || script)``."""
    return _tagged_hash("TapLeaf", bytes([version]), _compact_size(len(script)), script)


def taproot_tweak(internal_key: bytes, merkle_root: bytes = b"") -> tuple[bytes, bool]:
    """``Q = lift_x(P) + tagged_hash("TapTweak", P || merkle_root)·G``, as
    ``(x-only Q, Q has odd y)``. ``merkle_root`` is 32 bytes, or empty to
    commit to no script tree at all. Raises :class:`ProtocolError` when ``P``
    is no curve point or the tweak is out of range, which BIP-341 fails
    rather than reduces."""
    if len(merkle_root) not in (0, 32):
        raise ProtocolError("a merkle root is 32 bytes, or empty")
    internal = _lift_x(internal_key)
    if internal is None:
        raise ProtocolError("that key is not the x coordinate of a point on the curve")
    t = int.from_bytes(_tagged_hash("TapTweak", bytes(internal_key), bytes(merkle_root)), "big")
    if t >= _CURVE_N:
        raise ProtocolError("that taproot tweak is out of range")
    try:
        # coincurve refuses the point at infinity, the one other way out
        point = internal.add(t.to_bytes(32, "big")) if t else internal
    except ValueError as err:
        raise ProtocolError("that taproot tweak lands on the point at infinity") from err
    compressed = point.format(compressed=True)
    return compressed[1:], compressed[0] == 0x03


def output_key_of(script: bytes, control_block: bytes) -> bytes | None:
    """The ``Q`` a leaf and its control block commit to: the leaf hash folded
    up the merkle path with TapBranch, then the control block's internal key
    tweaked by the root. The control block's parity bit is checked too, so a
    ``Q`` returned here is exactly the one the spend is valid against. None
    for a malformed control block; never raises."""
    if len(control_block) < 33 or (len(control_block) - 33) % 32:
        return None
    if (len(control_block) - 33) // 32 > _MAX_MERKLE_DEPTH:
        return None
    node = tap_leaf_hash(script, control_block[0] & 0xFE)
    for i in range(33, len(control_block), 32):
        sibling = bytes(control_block[i : i + 32])
        low, high = sorted((node, sibling))
        node = _tagged_hash("TapBranch", low, high)
    try:
        q, odd = taproot_tweak(bytes(control_block[1:33]), node)
    except ProtocolError:
        return None
    if odd != bool(control_block[0] & 1):
        return None
    return q


# ---- the bearer note ----
#
# NUMS internal key and one OP_SHA256 <h> OP_EQUAL leaf: spent by revealing the
# preimage, with no signature, and so bound to no mint. Everything but the
# preimage follows from h, which is why its short forms work.


def bearer_leaf(h: bytes) -> bytes:
    """A bearer note's one leaf script, ``OP_SHA256 <h> OP_EQUAL``."""
    if len(h) != 32:
        raise ProtocolError("a bearer note's h is 32 bytes")
    return b"\xa8\x20" + bytes(h) + b"\x87"


@dataclass(frozen=True)
class BearerNote:
    """Everything about a bearer note that follows from its ``h``."""

    output_key: bytes
    control_block: bytes
    leaf: bytes


def bearer_note(h: bytes) -> BearerNote:
    """The bearer note whose hashlock is ``h``."""
    leaf = bearer_leaf(h)
    # NUMS_KEY is a point, and a hash at or above n is a 2^-128 event
    q, odd = taproot_tweak(NUMS_KEY, tap_leaf_hash(leaf))
    return BearerNote(q, bytes([TAPLEAF_VERSION | int(odd)]) + NUMS_KEY, leaf)


def bearer_note_id(h: str) -> str:
    """``hex(Q)`` for the bearer note named by its hex ``h``: the id a mint
    files, burns and certifies it under."""
    if not isinstance(h, str) or not is_preimage(h):
        raise ProtocolError("a bearer note's h is 32 bytes of hex")
    return bearer_note(bytes.fromhex(h.strip())).output_key.hex()


def bearer_cw1(preimage: str) -> str:
    """The full ``cw1`` a bearer note's preimage is the short form of: its
    leaf and control block, witness ``[preimage]``, locktime 0 and sequence
    0xffffffff. The same spend, three times the length."""
    if not isinstance(preimage, str) or not is_preimage(preimage):
        raise ProtocolError("a bearer note's preimage is 32 bytes of hex")
    secret = bytes.fromhex(preimage.strip())
    note = bearer_note(sha256(secret).digest())
    return encode_cw1(
        Cw1(KEY_PATH_LOCKTIME, KEY_PATH_SEQUENCE, note.leaf, note.control_block, (secret,))
    )


def bearer_hash_of_leaf(script: bytes) -> bytes | None:
    """The ``h`` inside a leaf that is exactly a bearer note's, else None."""
    if len(script) == 35 and script[:2] == b"\xa8\x20" and script[34] == 0x87:
        return bytes(script[2:34])
    return None


# ---- what a signature signs ----


def spend_domain_of(value: str) -> str:
    """The domain a spend at ``value`` is bound to: the mint's full hostname,
    lowercased, never its scheme or port. ``value`` may be a note URL in any
    spelling (https, ``lnurlw://``, a bech32 LNURL), a withdraw link, or a
    bare host."""
    trimmed = value.strip() if isinstance(value, str) else ""
    if is_bech32_lnurl(trimmed):
        trimmed = from_bech32_lnurl(trimmed) or ""
    expanded = from_lud17(trimmed)
    if "://" not in expanded:
        expanded = "https://" + expanded
    try:
        host = urlparse(expanded).hostname
    except ValueError:
        host = None
    if not host:
        raise ProtocolError("a spend is bound to a mint's domain, and that names no host")
    return host.lower()


def spend_prevout(domain: str) -> bytes:
    """The canonical spend transaction's prevout txid for a mint,
    ``tagged_hash("LNURLcash/mint", domain)``. This is what binds a signature
    to one mint."""
    return _tagged_hash("LNURLcash/mint", spend_domain_of(domain).encode())


def spend_sig_msg(
    output_key: bytes,
    domain: str,
    locktime: int,
    sequence: int,
    leaf_script: bytes | None = None,
) -> bytes:
    """BIP-341's SigMsg for input 0 of the canonical spend transaction under
    SIGHASH_DEFAULT: no ``leaf_script`` for a key path, or the leaf for a
    script path, which appends BIP-342's extension."""
    if len(output_key) != 32:
        raise ProtocolError("Q is 32 bytes")
    script_pubkey = b"\x51\x20" + bytes(output_key)
    msg = b"\x00"  # hash_type: SIGHASH_DEFAULT
    msg += struct.pack("<I", 2) + struct.pack("<I", locktime)
    msg += sha256(spend_prevout(domain) + struct.pack("<I", 0)).digest()  # sha_prevouts
    msg += sha256(struct.pack("<q", 0)).digest()  # sha_amounts
    msg += sha256(bytes([len(script_pubkey)]) + script_pubkey).digest()  # sha_scriptpubkeys
    msg += sha256(struct.pack("<I", sequence)).digest()  # sha_sequences
    msg += sha256(struct.pack("<q", 0) + b"\x00").digest()  # sha_outputs
    msg += bytes([0x00 if leaf_script is None else 0x02])  # spend_type, no annex
    msg += struct.pack("<I", 0)  # input_index
    if leaf_script is not None:
        # key_version 0, and no OP_CODESEPARATOR
        msg += tap_leaf_hash(leaf_script) + b"\x00" + b"\xff\xff\xff\xff"
    return msg


def _tap_sighash(sig_msg: bytes) -> bytes:
    return _tagged_hash("TapSighash", b"\x00", sig_msg)


def key_path_sighash(output_key: bytes, domain: str) -> bytes:
    """What a ``ck1``'s signature signs: the key-path sighash for this note at
    this mint, with no time claim."""
    return _tap_sighash(
        spend_sig_msg(output_key, domain, KEY_PATH_LOCKTIME, KEY_PATH_SEQUENCE)
    )


def script_path_sighash(
    output_key: bytes, domain: str, leaf_script: bytes, locktime: int, sequence: int
) -> bytes:
    """What a SIGHASH_DEFAULT signature inside a ``cw1``'s leaf signs, for the
    time the spend claims."""
    return _tap_sighash(spend_sig_msg(output_key, domain, locktime, sequence, bytes(leaf_script)))


# ---- cw1 ----


@dataclass(frozen=True)
class Cw1:
    """A script-path spend: the claimed time, the leaf, its control block, and
    the witness items the leaf consumes, bottom of the stack first."""

    locktime: int
    sequence: int
    script: bytes
    control_block: bytes
    witness: tuple[bytes, ...] = ()


def encode_cw1(spend: Cw1) -> str:
    """Encode a script-path spend. Whoever holds the result can spend the
    note, as far as the leaf allows."""
    if not (0 <= spend.locktime <= 0xFFFFFFFF and 0 <= spend.sequence <= 0xFFFFFFFF):
        raise ProtocolError("a cw1's locktime and sequence are each a u32")
    payload = struct.pack(">II", spend.locktime, spend.sequence)
    for item in (spend.script, spend.control_block, *spend.witness):
        if len(item) > _MAX_CW1_ITEM:
            raise ProtocolError("a cw1 item is at most 65535 bytes")
        payload += struct.pack(">H", len(item)) + bytes(item)
    return bech32.encode("cw", payload, _MAX_CW1_CHARS, constant=bech32.BECH32M)


def decode_cw1(value: str) -> Cw1 | None:
    """A ``cw1``'s parts, or None. Structure only: the length prefixes must
    consume the payload exactly, and a script and a control block must be
    there. Whether the control block commits to a key is
    :func:`output_key_of`'s question. Never raises."""
    if not isinstance(value, str):
        return None
    decoded = bech32.decode(value.strip(), _MAX_CW1_CHARS, constant=bech32.BECH32M)
    if decoded is None or decoded[0] != "cw" or len(decoded[1]) < 8:
        return None
    payload = decoded[1]
    locktime, sequence = struct.unpack(">II", payload[:8])
    items: list[bytes] = []
    i = 8
    while i < len(payload):
        if i + 2 > len(payload):
            return None
        (length,) = struct.unpack(">H", payload[i : i + 2])
        i += 2
        if i + length > len(payload):
            return None
        items.append(payload[i : i + length])
        i += length
    if len(items) < 2:
        return None
    return Cw1(locktime, sequence, items[0], items[1], tuple(items[2:]))


def is_cw1(value: str) -> bool:
    """Whether ``value`` is a well-formed ``cw1``, structurally."""
    return decode_cw1(value) is not None


def output_key_of_cw1(value: str) -> bytes | None:
    """The ``Q`` a ``cw1`` opens, recomputed from its leaf and control block.
    Nothing about its witness is checked. None for anything else."""
    spend = decode_cw1(value)
    return output_key_of(spend.script, spend.control_block) if spend else None


# ---- the leaf and time rules ----

# BIP-342's OP_SUCCESSx: 80, 98, 126-129, 131-134, 137-138, 141-142, 149-153
# and 187-254.
_OP_SUCCESS = frozenset(
    [80, 98, 137, 138, 141, 142]
    + list(range(126, 130))
    + list(range(131, 135))
    + list(range(149, 154))
    + list(range(187, 255))
)


def check_leaf_policy(version: int, script: bytes) -> str | None:
    """LUD-25's one exception to "anything consensus accepts": tapscript's
    upgrade hooks. A leaf version other than 0xc0, or an OP_SUCCESSx opcode
    anywhere outside pushed data, succeeds unconditionally under consensus
    today and would make the leaf spendable by anyone who saw it, so a mint
    refuses both before anything runs. ``version`` is the control block's
    first byte with the parity bit cleared.

    None when the leaf is allowed, else the reason it is not."""
    if version != TAPLEAF_VERSION:
        return f"leaf version 0x{version:02x} is not tapscript's 0xc0"
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if 0x01 <= op <= 0x4B:
            length = op
        elif op in (0x4C, 0x4D, 0x4E):
            width = {0x4C: 1, 0x4D: 2, 0x4E: 4}[op]
            if i + width > len(script):
                return "a push runs past the end of the leaf"
            length = int.from_bytes(script[i : i + width], "little")
            i += width
        else:
            if op in _OP_SUCCESS:
                return f"the leaf uses OP_SUCCESS{op}, a reserved upgrade hook"
            continue
        # consensus fails a script whose push is cut short before it could
        # ever reach an OP_SUCCESS after it
        if i + length > len(script):
            return "a push runs past the end of the leaf"
        i += length
    return None


_LOCKTIME_THRESHOLD = 500_000_000
_SEQUENCE_DISABLE_FLAG = 1 << 31
_SEQUENCE_TYPE_FLAG = 1 << 22
_SEQUENCE_VALUE_MASK = 0xFFFF
_SEQUENCE_GRANULARITY_S = 512


def check_time_claim(locktime: int, sequence: int, now: int, locked_at: int) -> str | None:
    """Judge a script-path spend's claimed nLockTime and nSequence against a
    clock, in Unix seconds: ``now``, and ``locked_at``, when the mint credited
    the note. It is the mint's clock that decides, so a WALLET can only use
    this to predict the answer. A timelock a mint honours is the mint
    asserting its own clock, a custodial policy and never a trustless
    guarantee.

    None when the claim is due, else the reason it is not."""
    if locktime != 0:
        if locktime < _LOCKTIME_THRESHOLD:
            return "a block-height locktime has no meaning without a chain"
        if locktime > now:
            return f"locktime {locktime} has not been reached (now {now})"
    if sequence & _SEQUENCE_DISABLE_FLAG:
        return None
    if not sequence & _SEQUENCE_TYPE_FLAG:
        return "a block-count relative lock has no meaning without a chain"
    required = (sequence & _SEQUENCE_VALUE_MASK) * _SEQUENCE_GRANULARITY_S
    elapsed = now - locked_at
    if elapsed < required:
        return f"a relative lock of {required}s has not yet run ({max(elapsed, 0)}s elapsed)"
    return None
