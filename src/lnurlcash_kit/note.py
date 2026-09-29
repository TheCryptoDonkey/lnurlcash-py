"""Note URLs: parsing what a note claims, and building the next one."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .errors import ProtocolError
from .recoverable import decode_cs1_with_amount, is_cp1, is_cs1_with_amount, verify_spend
from .secrets import is_preimage
from .urls import from_lud17, resolve_lnurl_input


def _query_pairs(url: str) -> list[tuple[str, str]]:
    return parse_qsl(urlparse(url).query, keep_blank_values=True)


def _first(url: str, key: str) -> str | None:
    for k, v in _query_pairs(url):
        if k == key:
            return v
    return None


def _rebuild(url: str, pairs: list[tuple[str, str]]) -> str:
    parts = urlparse(url)
    return urlunparse(parts._replace(query=urlencode(pairs)))


def note_k1(url: str) -> str | None:
    """The secret out of a note URL, normalised to lowercase hex: it is bytes,
    not text, so casing carries no meaning, and normalising keeps duplicate
    detection and the echo check on an informational GET from treating the
    same secret in two casings as two different notes."""
    try:
        value = _first(url, "k1")
    except ValueError:
        return None
    return value.lower() if value is not None else None


def require_note_k1(url: str) -> str:
    """Like ``note_k1`` but raises. A hardware-backed note deliberately carries
    no secret in its URL, so a caller about to use one for a mutation should
    use this: it fails loudly instead of quietly sending a blank k1."""
    k1 = note_k1(url)
    if not k1:
        raise ValueError(
            "This note carries no secret in its URL - it may be held on a device."
        )
    return k1


def note_declared_amount(url: str) -> int | None:
    """What a note CLAIMS to carry. Only a claim by whoever encoded it - a
    SERVICE ignores it at the informational endpoint - so it is safe to display
    before contacting the SERVICE but must not be trusted without either a
    matching signature or a fresh online GET. When there is no separate
    ``amount``, a current amount-bearing ``cs1`` carries the same declaration
    in its prefix."""
    try:
        raw = _first(url, "amount")
    except ValueError:
        return None
    if raw is None:
        signature = _first(url, "sig")
        certificate = decode_cs1_with_amount(signature) if signature else None
        return certificate.amount_msat if certificate is not None else None
    try:
        return int(raw)
    except ValueError:
        try:
            value = float(raw)
        except ValueError:
            return None
        return int(value) if value.is_integer() else None


def note_signature(url: str) -> str | None:
    try:
        return _first(url, "sig")
    except ValueError:
        return None


def resolve_note_input(value: str) -> str | None:
    """Input only qualifies as a note if it resolves to a URL whose k1 is a
    spend that opens its note at the URL's own domain
    (:func:`~lnurlcash_kit.recoverable.verify_spend`): a bearer preimage or
    cw1, or a ck1 signed for this mint. A ck1 signed for another mint could
    never be redeemed here, so it is refused at the door. A cw1 whose leaf
    this library cannot run passes on its structure alone; the mint judges
    the rest. A cp1 is a note's public name, not a spend, so it does not
    qualify."""
    url = resolve_lnurl_input(value)
    if not url:
        return None
    k1 = note_k1(url)
    if not k1 or verify_spend(k1, url) is None:
        return None
    return url


def is_valid_note_input(value: str) -> bool:
    return resolve_note_input(value) is not None


def build_note_url(
    withdraw_link: str, k1: str, amount_msat: int | None = None
) -> str:
    """A withdrawLink plus a secret makes a note. Omit ``amount_msat`` when the
    real value is not known yet: the spec has a SERVICE ignore it here
    regardless, but some implementations validate it strictly, and a
    placeholder like 0 risks being rejected rather than ignored."""
    url = from_lud17(withdraw_link.strip())
    pairs = [(k, v) for k, v in _query_pairs(url) if k not in ("k1", "amount")]
    pairs.append(("k1", k1.strip().lower()))
    if amount_msat is not None:
        pairs.append(("amount", str(amount_msat)))
    return _rebuild(url, pairs)


def build_note_info_url_by_hash(withdraw_link: str, h: str) -> str:
    """The informational GET for a note named by its public name rather than
    a spend of it.

    LUD-25's "Checking a note without exposing it": a SERVICE MUST accept
    ``?p=<cp1>`` in place of ``?k1=``, or a bearer note's hex ``h`` as its
    short form, on the informational GET only and never at the callback. The
    spend stays off the wire, which is what a restore walk needs, since a walk
    queries a whole gap window of indices the wallet has not minted into yet.

    ``k1``, ``amount`` and ``sig`` are dropped: naming the note twice, once in
    a form that spends it, would defeat the point.

    An unknown note is answered exactly as an unknown ``k1`` is, and a burned
    note is deliberately indistinguishable from one that never existed.

    ``h`` is a cp1 or a bearer note's hex ``h``, and goes as ``p`` either way.
    Mints from before LUD-25 settled on ``p`` also read ``h``, but every
    current one reads ``p`` for both.
    :func:`~lnurlcash_kit.recoverable.note_lookup_of` gives the right value
    for any k1.
    """
    value = h.strip().lower()
    if not is_cp1(value) and not is_preimage(value):
        raise ProtocolError("a note lookup is a bearer note's 32-byte hex h, or a cp1")
    url = from_lud17(withdraw_link.strip())
    pairs = [(k, v) for k, v in _query_pairs(url) if k not in ("k1", "amount", "sig")]
    pairs.append(("p", value))
    return _rebuild(url, pairs)


def with_new_k1(
    url: str, k1: str, amount_msat: int, signature: str | None = None
) -> str:
    """The same note with its secret swapped out, after a rotate, split or
    merge. A signature only carries over when the response actually returned a
    fresh one: a mutation at a SERVICE without offline verification drops any
    stale sig, since it no longer matches the new secret."""
    amount_is_implied = bool(signature) and is_cs1_with_amount(signature)
    pairs: list[tuple[str, str]] = []
    replaced = {"k1": False, "amount": False, "sig": False}
    for key, value in _query_pairs(url):
        if key == "k1":
            pairs.append((key, k1.lower()))
            replaced["k1"] = True
        elif key == "amount":
            if not amount_is_implied:
                pairs.append((key, str(amount_msat)))
                replaced["amount"] = True
        elif key == "sig":
            if signature:
                pairs.append((key, signature))
                replaced["sig"] = True
        else:
            pairs.append((key, value))
    if not replaced["k1"]:
        pairs.append(("k1", k1.lower()))
    if not replaced["amount"] and not amount_is_implied:
        pairs.append(("amount", str(amount_msat)))
    if signature and not replaced["sig"]:
        pairs.append(("sig", signature))
    return _rebuild(url, pairs)


def without_k1(url: str, amount_msat: int, signature: str | None = None) -> str:
    """Like ``with_new_k1`` but removes k1 - for re-deriving a hardware-backed
    note's blank URL template after a mutation whose fresh secret now lives on
    the device rather than in this process."""
    amount_is_implied = bool(signature) and is_cs1_with_amount(signature)
    pairs: list[tuple[str, str]] = []
    seen_amount = False
    seen_sig = False
    for key, value in _query_pairs(url):
        if key == "k1":
            continue
        if key == "amount":
            if not amount_is_implied:
                pairs.append((key, str(amount_msat)))
                seen_amount = True
        elif key == "sig":
            if signature:
                pairs.append((key, signature))
                seen_sig = True
        else:
            pairs.append((key, value))
    if not seen_amount and not amount_is_implied:
        pairs.append(("amount", str(amount_msat)))
    if signature and not seen_sig:
        pairs.append(("sig", signature))
    return _rebuild(url, pairs)
