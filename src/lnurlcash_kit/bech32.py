"""bech32, as LUD-01 uses it, and bech32m, as LUD-25's own values do.

The reference implementation from BIP-173, by Pieter Wuille, vendored rather
than pulled in as a dependency: it is sixty lines of checksum arithmetic with
no crypto in it, and a bearer-money library is better off with one fewer
supply-chain edge. LNURL raises the length limit well above bech32's default,
because a note URL carrying k1, amount and sig is long.

bech32m (BIP-350) differs from bech32 in one constant, the value the checksum
is XORed with, so it is the same code with that constant passed in. The two
never verify each other's strings: a caller names the one it expects, and
LUD-01 decoding is exactly what it was.
"""

from __future__ import annotations

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

#: BIP-173's checksum constant: plain bech32, which LUD-01 uses.
BECH32 = 1
#: BIP-350's: bech32m, which LUD-25's cp1, ck1, cw1, cs1 and cx1 use.
BECH32M = 0x2BC830A3


def _polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _verify_checksum(hrp: str, data: list[int], constant: int) -> bool:
    return _polymod(_hrp_expand(hrp) + data) == constant


def _create_checksum(hrp: str, data: list[int], constant: int) -> list[int]:
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ constant
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def convertbits(
    data: bytes | list[int], frombits: int, tobits: int, pad: bool = True
) -> list[int] | None:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def encode(hrp: str, data: bytes, limit: int = 2048, *, constant: int = BECH32) -> str:
    converted = convertbits(data, 8, 5)
    if converted is None:
        raise ValueError("could not convert to 5-bit groups")
    combined = converted + _create_checksum(hrp, converted, constant)
    result = hrp + "1" + "".join([CHARSET[d] for d in combined])
    if len(result) > limit:
        raise ValueError(f"encoded length {len(result)} exceeds limit {limit}")
    return result


def decode(
    bech: str, limit: int = 2048, *, constant: int = BECH32
) -> tuple[str, bytes] | None:
    """``(hrp, payload)``, or None for anything that is not a well-formed
    string under ``constant``: mixed case, a checksum made with the other
    constant, or padding bits that are not zero (BIP-173 and BIP-350 both
    refuse all three). The hrp comes back lowercase."""
    if (any(ord(x) < 33 or ord(x) > 126 for x in bech)) or (
        bech.lower() != bech and bech.upper() != bech
    ):
        return None
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > limit:
        return None
    if not all(x in CHARSET for x in bech[pos + 1 :]):
        return None
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos + 1 :]]
    if not _verify_checksum(hrp, data, constant):
        return None
    decoded = convertbits(data[:-6], 5, 8, False)
    if decoded is None:
        return None
    return hrp, bytes(decoded)
