"""LUD-25's ``m/139'`` branch derivation: the BIP-32 walk from a wallet's cash
root down to a per-SERVICE domain node, exactly as its "Seed & derivation"
section specifies it::

    cashHashingKey   = derive(masterKey, m/139'/0)
    domainMaterial   = hmacSha256(cashHashingKey, full SERVICE domain)
    (d1, d2, d3, d4) = first 16 bytes of domainMaterial as 4 uint32
    domainNode       = derive(masterKey, m/139'/d1/d2/d3/d4)

"exactly as LUD-05", says the draft of the middle two lines, and that
reference settles the one thing the path shape leaves open. ``d1..d4`` are raw
uint32 drawn from a hash, and BIP-32 already reads any index >= 2^31 as
hardened, so roughly half of any given mint's four levels are hardened by
magnitude alone. They are used exactly as they fall: nothing is masked, and
nothing is forced hardened. That is what LUD-05's own corpus does with the same
four longs, and what the reference wallet does.

An implementation that masks the top bit, or hardens all four, derives a
different tree from every conforming wallet - and a restore against it finds
nothing, silently, and only once the money is gone.

Bearer preimages are NOT derived from this node, or from the seed at all -
LUD-25 has WALLET generate plain randomness. An earlier reference-wallet
extension did derive them deterministically from a sibling of this branch,
hardened at the note's own index; it has since been dropped as unspecified,
and this module no longer provides it.
:mod:`~lnurlcash_kit.secrets`' legacy scheme (HMAC-SHA256 under
``lnurlcash-note-v1``, predating LUD-25 entirely) is still derived and still
scanned on restore, so nothing already minted under it goes missing.

The key-path notes' address branch is this exact domain node, for the same
host: see :func:`~lnurlcash_kit.recoverable.derive_cash_address_node`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from hashlib import sha256, sha512

from coincurve import PrivateKey

from .errors import ProtocolError

_HARDENED = 0x80000000
_CASH_PURPOSE = 139


@dataclass(frozen=True)
class CashNode:
    """A BIP-32 extended private key, reduced to the two things deriving a
    child actually needs.

    Bearer material for every note derived beneath it. A domain node is the
    unit a hardware signer is provisioned with (see :func:`cash_node_to_hex`),
    so this is plain bytes rather than an xprv.
    """

    private_key: bytes
    chain_code: bytes

    def __repr__(self) -> str:  # pragma: no cover - trivial
        # Redacted deliberately. The surest way to leak a node is a dataclass
        # that prints itself into a log line somebody added while debugging
        # something else.
        return "CashNode(redacted)"


def _hmac512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, sha512).digest()


def derive_cash_child(node: CashNode, index: int) -> CashNode:
    """One BIP-32 CKDpriv step.

    Hardened when ``index >= 2**31``, by the index's own magnitude and nothing
    else, which is the whole of the convention question above: the caller
    passes the raw uint32 and this decides.

    Public so a consumer can check this package against BIP-32's own published
    test vectors rather than taking the derivation on trust, and so a host
    provisioning a hardware signer can walk the intermediate levels.
    """
    if not 0 <= index <= 0xFFFFFFFF:
        raise ProtocolError(f"a BIP-32 child index must be a uint32, not {index}")
    try:
        parent = PrivateKey(node.private_key)
    except ValueError as err:
        raise ProtocolError("cash node holds an invalid private key") from err

    if index >= _HARDENED:
        # 0x00 || ser256(kpar): the leading zero pads the 32-byte scalar out to
        # the 33 bytes a serialised point occupies, so the two legs hash over
        # the same length and can never collide.
        data = b"\x00" + node.private_key
    else:
        data = parent.public_key.format(compressed=True)
    data += index.to_bytes(4, "big")

    material = _hmac512(node.chain_code, data)
    # "In case parse256(IL) >= n or ki = 0, proceed with the next value for i."
    # Both are ~2^-127 events and no wallet will ever see one, but a silently
    # wrong answer here is a note nobody can spend, so coincurve's own range
    # check is allowed to speak rather than being caught and ignored.
    try:
        child = parent.add(material[:32])
    except ValueError as err:
        raise ProtocolError(f"BIP-32 derivation at {index} is out of range") from err
    return CashNode(child.secret, material[32:])


def _master_from(seed: bytes) -> CashNode:
    if not 16 <= len(seed) <= 64:
        raise ProtocolError(f"a BIP-32 seed must be 16 to 64 bytes, not {len(seed)}")
    material = _hmac512(b"Bitcoin seed", seed)
    try:
        PrivateKey(material[:32])
    except ValueError as err:
        raise ProtocolError("this seed does not produce a valid BIP-32 master key") from err
    return CashNode(material[:32], material[32:])


def derive_cash_master(seed: bytes) -> CashNode:
    """The BIP-32 master node of a seed.

    Public beside :func:`derive_cash_child` for the same reason: a consumer
    walking a path this package does not name (nsec-tree's
    ``m/44'/1237'/727'/0'/0'``, say) starts here.
    """
    return _master_from(seed)


def derive_cash_root(seed: bytes) -> CashNode:
    """``m/139'`` - the wallet's own root for key-path note keys, under its own
    purpose so it never shares key material with LUD-05's ``m/138'``
    linking-key branch.

    ``seed`` is raw bytes. A 64-byte BIP39 seed is the interop case, and what
    the reference wallet feeds in, but nothing here depends on BIP39 - which is
    also what keeps a mnemonic wordlist out of every consumer's environment.
    """
    return derive_cash_child(_master_from(seed), _CASH_PURPOSE + _HARDENED)


def cash_domain_indices(root: CashNode, host: str) -> tuple[int, int, int, int]:
    """The four raw uint32 levels a mint's subtree hangs off.

    Public because they are the whole of what a conformance vector has to pin,
    and because a wallet debugging a restore that finds nothing wants them.
    """
    hashing = derive_cash_child(root, 0)
    material = hmac.new(hashing.private_key, host.encode("utf-8"), sha256).digest()
    return tuple(  # type: ignore[return-value]
        int.from_bytes(material[at : at + 4], "big") for at in (0, 4, 8, 12)
    )


def derive_cash_domain_node(root: CashNode, host: str) -> CashNode:
    """``m/139'/d1/d2/d3/d4`` for one mint: the key-path notes' address branch
    (:func:`~lnurlcash_kit.recoverable.derive_cash_address_node` is this node).

    Whoever holds it can derive every note key the wallet will ever hold
    AT THIS MINT, so it is provisioning material rather than something to hand
    out: one mint's subtree, not the wallet. Hand out its cx1 instead.

    ``host`` is the mint host exactly as the wallet stores it - lowercase, port
    included where there is one - which is what the reference wallet passes, so
    the two derive the same tree.
    """
    node = root
    for index in cash_domain_indices(root, host):
        node = derive_cash_child(node, index)
    return node


def cash_node_to_hex(node: CashNode) -> str:
    """``privateKey || chainCode``, 64 bytes of hex.

    Not a BIP-32 extended key: no version bytes, no depth, no parent
    fingerprint, no base58check. This is the same 64 bytes the reference wallet
    persists for its own root and the shape a hardware signer is provisioned
    with, and nothing here is ever meant to leave a wallet as a portable xprv.
    """
    return node.private_key.hex() + node.chain_code.hex()


def cash_node_from_hex(value: str) -> CashNode:
    try:
        raw = bytes.fromhex(value.strip().lower())
    except ValueError as err:
        raise ProtocolError("a cash node is 64 bytes of hex") from err
    if len(raw) != 64:
        raise ProtocolError(
            f"a cash node is 64 bytes - a 32-byte key and a 32-byte chain code - not {len(raw)}"
        )
    try:
        PrivateKey(raw[:32])
    except ValueError as err:
        raise ProtocolError("that cash node holds an invalid private key") from err
    return CashNode(raw[:32], raw[32:])
