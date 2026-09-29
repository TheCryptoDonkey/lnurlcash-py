"""Note secrets: where they come from, and what shape they are."""

from __future__ import annotations

import hmac
import re
import secrets as _secrets
from hashlib import sha256

_PREIMAGE_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def hash_k1(k1: str) -> str:
    """A bearer preimage's ``h = sha256(k1)``: the short form a WALLET
    discloses as ``p1``, ``p2`` or a mint comment to name the bearer note. The
    note itself is filed under ``hex(Q)``, which follows from ``h``
    (:func:`~lnurlcash_kit.spend.bearer_note_id`); ``h`` never reveals the
    preimage."""
    return sha256(bytes.fromhex(k1)).hexdigest()


def generate_note_secret() -> str:
    """LUD-25: the WALLET - never the SERVICE - generates every note it will
    hold, here a bearer note's preimage, and discloses only its public name.

    A fresh 32 bytes, the same size a Lightning payment preimage is, though
    nothing is ever paid for it. Drawn from the OS CSPRNG. A caller passing
    its own generator (for a hardware RNG, or a deterministic test) takes
    responsibility for unpredictability: anything guessable is a note anyone
    can spend.
    """
    return _secrets.token_hex(32)


def is_preimage(value: str) -> bool:
    """A payment preimage, and therefore a note secret: 32 bytes hex."""
    return bool(_PREIMAGE_RE.match(value.strip()))


# ---- the legacy derivation ----
#
# This project shipped this scheme before LUD-25 had a section on deriving note
# secrets at all::
#
#     root = HMAC-SHA256(key = utf8("lnurlcash-note-v1"), msg = seed)
#     k1_i = HMAC-SHA256(key = root,                      msg = utf8(host + ":" + index))
#
# It is NOT what a new wallet should mint under - see :mod:`lnurlcash_kit.cash`
# for the scheme the draft actually specifies. It is here because notes minted
# under it are still money, and a restore that walked only the current scheme
# would leave them at a mint it can no longer name.

_NOTE_DERIVATION_DOMAIN = b"lnurlcash-note-v1"


def derive_note_root(seed: bytes) -> bytes:
    """The legacy scheme's root. ``seed`` is raw bytes, of any length."""
    return hmac.new(_NOTE_DERIVATION_DOMAIN, seed, sha256).digest()


def derive_note_secret(root: bytes, host: str, index: int) -> str:
    """The legacy scheme's i-th secret at ``host``, as 32 bytes of hex.

    ``host`` is the mint host as the wallet stores it - lowercase, port
    included where there is one - and ``index`` counts from 0.
    """
    return hmac.new(root, f"{host}:{index}".encode("utf-8"), sha256).hexdigest()
