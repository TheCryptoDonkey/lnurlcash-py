"""The protocol itself, with no I/O in it.

Every operation is described as a :class:`Request` - a URL to GET, a function
to parse what comes back, and the fresh secrets that must survive if the
answer is lost. The clients in :mod:`lnurlcash_kit.client` do nothing but
perform the GET and hand the body to the parser, which is why the sync and
async clients cannot drift apart in any way that matters.

It also means a caller with its own HTTP stack - an aiohttp service, a
requests-based script, something behind a proxy - can use this module
directly and never touch the clients at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .errors import (
    AmbiguousMint,
    NotePending,
    ProtocolError,
    RequestRefused,
    ServiceRejected,
    UnverifiableNote,
    classify_note_error,
)
from .fees import _MAX_SAFE_INT, MintFee, parse_mint_fee
from .bolt11 import decode_bolt11_amount_msat
from .note import note_k1
from .recoverable import is_cp1, verify_spend
from .secrets import generate_note_secret, hash_k1, is_preimage
from .urls import is_allowed_service_url


@dataclass
class Request:
    """One GET, and everything needed to interpret its outcome."""

    url: str
    parse: Callable[[Any], Any]
    #: fresh WALLET-generated bearer preimages this request disclosed the
    #: hashes of. If the outcome is unknown they may be the only copies of
    #: notes the SERVICE has already minted, so they must ride the failure out.
    new_secrets: list[str] = field(default_factory=list)
    #: whether a client may re-send this request when the transport loses its
    #: answer. True for a rotate, split or merge, which LUD-25 requires a
    #: SERVICE to answer as a replay of the original success ("Retrying a
    #: mutation"). False for everything else, and for a melt above all: it
    #: carries ``pr``, is paid out asynchronously, and has no replay guarantee,
    #: so a second request could ask for a second payment.
    replayable: bool = False


@dataclass(frozen=True)
class Policy:
    """What this library insists a SERVICE does, rather than merely hopes.

    LUD-25 has a SERVICE certify every note it issues (a SHOULD), a bearer
    note included, since every note now has a public ``Q``. This library goes
    further for an output the caller named by ``cp1``: a rotate, split or
    merge to one MUST come back with its ``cs1`` in ``c`` (``c2`` for a
    split's change), because offline verification is the reason to name a
    note that way, and nothing here turns it off. An output named by a bearer
    note's hex ``h`` may come back uncertified, as it does from a mint with no
    signer.

    ``require_signatures`` demands a certificate for an output named by a
    bearer ``h`` too. It is off by default to admit a mint with no signer.

    ``require_mint_pubkey`` refuses a ``withdrawRequest`` that publishes no
    valid ``mintPubkey``, the key every certificate verifies against. On by
    default. Set it false only for a SERVICE that publishes none, knowing
    that nothing it issues can then be checked offline.
    """

    require_signatures: bool = False
    require_mint_pubkey: bool = True


#: What a caller gets without stating a policy: a ``cs1`` on every output
#: named by ``cp1``, a ``mintPubkey`` on every ``withdrawRequest``, and an
#: output named by a bearer ``h`` taken certified or not.
DEFAULT_POLICY = Policy()


def is_compressed_pubkey(value: Any) -> bool:
    """Whether ``value`` is a compressed secp256k1 point: 33 bytes hex, the
    leading byte naming which of the two y values the x coordinate stands for.

    Checked at the response rather than at the first signature check, because
    a ``mintPubkey`` that is not one verifies nothing - and the same fault
    found later looks like a forged note instead of a broken mint.
    """
    if not isinstance(value, str):
        return False
    key = value.strip().lower()
    return (
        len(key) == 66
        and key[:2] in ("02", "03")
        and all(char in "0123456789abcdef" for char in key)
    )


@dataclass(frozen=True)
class WithdrawRequestInfo:
    callback: str
    k1: str
    max_withdrawable: int
    min_withdrawable: int = 0
    default_description: str | None = None
    #: The key every certificate from this SERVICE verifies against. Only
    #: ever None when the caller passed a Policy with ``require_mint_pubkey``
    #: false.
    mint_pubkey: str | None = None
    #: the response's ``c``: the SERVICE's cs1 certificate over the note's
    #: ``hex(Q)`` and current amount, so a holder need not force a rotate just
    #: to get one. Passed on as sent and never checked here -
    #: :func:`~lnurlcash_kit.signature.verify_note_signature` is the check.
    #: None when the SERVICE sent none, as a mint with no signer does
    signature: str | None = None


@dataclass(frozen=True)
class NoteInfoByHash:
    """What a lookup by ``p`` returns.

    Deliberately NOT :class:`WithdrawRequestInfo`: that type's ``k1`` is the
    spend, and the whole point of asking by a public name is that the caller
    already holds it and the SERVICE never sends it back. A conforming SERVICE
    omits ``k1`` here (LUD-03's convenience of echoing the queried value has
    nothing to echo), so a type promising one would be promising something no
    answer contains.
    """

    callback: str
    max_withdrawable: int
    min_withdrawable: int = 0
    default_description: str | None = None
    mint_pubkey: str | None = None
    #: as on :class:`WithdrawRequestInfo`: the note's cs1, which is what makes
    #: a lookup by cp1 enough to rebuild a verifiable note on restore
    signature: str | None = None


@dataclass(frozen=True)
class MintAddressInfo:
    callback: str
    pay_link: str
    max_withdrawable: int
    min_withdrawable: int = 0
    #: the wire field is ``mintPubkey``, but at this endpoint it is never a
    #: note's signing key - always the SERVICE's own node identity
    node_pubkey: str | None = None
    node_alias: str | None = None
    node_uri: str | None = None
    node_color: str | None = None
    #: the wire field is ``nodeCapacity``, msat like every other amount here -
    #: suffixed on this side so a caller cannot read it as sats
    node_capacity_msat: int | None = None
    node_num_channels: int | None = None
    node_num_peers: int | None = None
    #: every address the SERVICE's node announces, each already
    #: ``node_key@host:port``. ``node_uri`` is the first of them; a node behind
    #: Tor as well as clearnet has more, and a caller that can only reach the
    #: other one needs the whole list. ``None``, never an empty list, when the
    #: SERVICE announces nothing
    node_uris: tuple[str, ...] | None = None
    #: the day the SERVICE plans to close, ISO-8601 (``"2026-12-31"``).
    #: Advance warning while there is still time to spend, deliberately not the
    #: same thing as a mint that has already stopped minting. Nothing enforces
    #: it and nothing verifies it, so it is a prompt to move notes, never a
    #: deadline to compute against. ``None`` when the SERVICE published none, or
    #: published something that is not a real calendar day
    sunset_date: str | None = None
    #: what the SERVICE says it owes, msat: every note it has issued and not
    #: burned. Its own claim about its own database, with nothing to check it
    #: against, so read it next to what the node holds rather than on its own.
    #: ``0`` and ``None`` are different answers
    outstanding_notes_msat: int | None = None


@dataclass(frozen=True)
class PayRequestInfo:
    callback: str
    min_sendable: int
    max_sendable: int
    metadata: str
    #: Present when paying this mints a bearer note: the raw LUD-17 withdraw
    #: endpoint, in either the plain or the ``lnurlw://`` spelling. The draft
    #: says "as described in LUD-17", and LUD-17 describes both, so a WALLET
    #: accepts either unchanged.
    withdraw_link: str | None = None
    mint_pubkey: str | None = None
    #: ``None`` means the SERVICE advertised no fee, which the draft says to
    #: read as fee-free rather than as unknown.
    mint_fee: MintFee | None = None
    #: LUD-12's field, and LUD-25's minting capability. A mint MUST allow the
    #: 64 characters a bearer note's hex ``h`` needs; a cp1 is 61.
    comment_allowed: int | None = None
    #: Additive ForgeSworn extension: this SERVICE also accepts the same
    #: commitment as an ``h`` parameter. Never a substitute for the mandatory
    #: comment, and anything that is not exactly ``True`` reads as false.
    mint_to_hash: bool = False

    def names_mint_output(self) -> bool:
        """Whether this SERVICE can mint a current-draft LUD-25 note.

        ``mint_to_hash`` alone cannot stand in for it: that extension is
        additive and predates the comment spelling, and a SERVICE without the
        comment capacity has nowhere to put the commitment.
        """
        return (
            self.comment_allowed is not None
            and self.comment_allowed >= MINT_COMMENT_LENGTH
        )


#: The comment capacity minting needs: a bearer note's ``h``, 32 bytes as
#: lowercase hex. A cp1 is 61 characters, so it fits the same.
MINT_COMMENT_LENGTH = 64


@dataclass(frozen=True)
class InvoiceResult:
    pr: str
    verify: str | None = None
    #: LUD-11: absent MUST be read as True, so only an explicit False counts
    disposable: bool = True


@dataclass(frozen=True)
class VerifyResult:
    settled: bool
    preimage: str | None
    pr: str


@dataclass(frozen=True)
class MeltResult:
    pr: str | None = None
    verify: str | None = None


@dataclass(frozen=True)
class MutationResult:
    signature: str | None = None
    change_signature: str | None = None


@dataclass(frozen=True)
class RotateResult:
    k1: str
    signature: str | None = None


@dataclass(frozen=True)
class SplitResult:
    k1: str
    change: str
    signature: str | None = None
    change_signature: str | None = None


def _with_params(url: str, params: list[tuple[str, str]]) -> str:
    """Append, never replace: a merge repeats the k1 parameter, and a callback
    may already carry parameters of its own."""
    parts = urlparse(url)
    existing = parse_qsl(parts.query, keep_blank_values=True)
    return urlunparse(parts._replace(query=urlencode(existing + params)))


def _optional_int(value: Any) -> int | None:
    """An informational count or amount, or nothing. A SERVICE that sends
    something other than a number for one is not worth failing the whole
    response over - these fields are display only."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _msat(value: Any) -> int | None:
    """An amount read exactly, or None: a JSON integer from 0 to 2^53 - 1.

    json.loads never makes a fraction an int, so 21000.5 arrives as a float
    and is refused here. A Python int has no ceiling, though, so a SERVICE
    answering 18446744073709552000 would otherwise be taken at its word. Past
    2^53 an integer is not guaranteed to mean the same number in every
    implementation (RFC 8259, section 6), so the one a SERVICE wrote need not
    be the one it meant, and it is refused rather than guessed at. The same
    bound the fee parser applies, and lnurlcash-kit too.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= _MAX_SAFE_INT else None


def _withdraw_amounts(body: dict) -> tuple[int, int]:
    """A withdrawRequest's maxWithdrawable and minWithdrawable, each read by
    :func:`_msat`. An absent or null minWithdrawable is zero. Anything else
    that fails the read, or a minimum above the maximum, is not a
    withdrawRequest."""
    maximum = _msat(body.get("maxWithdrawable"))
    raw_minimum = body.get("minWithdrawable")
    minimum = 0 if raw_minimum is None else _msat(raw_minimum)
    if maximum is None or minimum is None or minimum > maximum:
        raise ProtocolError("Not a withdrawRequest (unexpected response).")
    return maximum, minimum


def _optional_str_tuple(value: Any) -> tuple[str, ...] | None:
    """Non-empty strings only, and None rather than an empty tuple for a list
    that had none: a caller testing ``is not None`` and one testing ``len()``
    have to reach the same conclusion about a SERVICE that announced nothing."""
    if not isinstance(value, list):
        return None
    entries = tuple(item for item in value if isinstance(item, str) and item)
    return entries or None


def _optional_iso_date(value: Any) -> str | None:
    """A calendar day, ``YYYY-MM-DD``, and nothing else.

    A timestamp, a locale-formatted date or a typo is dropped rather than
    passed on, because the one thing a WALLET does with this is put it in
    front of a holder and a wrong date there is worse than no date.
    ``date.fromisoformat`` refuses 2026-02-31 outright rather than rolling it
    forward to March, and the re-format catches the spellings it accepts that
    are not this one."""
    if not isinstance(value, str):
        return None
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        return None
    return value if parsed.isoformat() == value else None


def _certificate_field(body: dict, name: str, legacy: str) -> Any:
    """A certificate as LUD-25 names it (``c``, ``c2``). ``legacy`` (``sig``,
    ``sig2``) is what earlier drafts and mints called it, and is still READ
    when the current name is absent; nothing here sends it."""
    value = body.get(name)
    return value if value is not None else body.get(legacy)


def _optional_signature(body: dict) -> str | None:
    """An informational GET's ``c`` (or legacy ``sig``), or nothing. Display
    and verification material only, so a SERVICE sending something that is not
    a string gets it dropped rather than the whole response refused."""
    value = _certificate_field(body, "c", "sig")
    return value if isinstance(value, str) and value else None


def _reject_error(body: Any) -> None:
    """A SERVICE's ERROR is definitive. The reason is carried through exactly
    as sent, empty included - see classify_note_error for why substituting a
    friendly default here would be a bug about somebody's money."""
    if isinstance(body, dict) and body.get("status") == "ERROR":
        reason = body.get("reason")
        raise ServiceRejected(reason if isinstance(reason, str) else "")


# ---- the informational GET ----


def _same_note(a: str, b: str, note_url: str) -> bool:
    """Whether two k1s name one note at the mint ``note_url`` is on.

    Exact spelling is preferred. A different spelling is the same note only
    when both open the same ``Q`` there: one note may have several valid
    spends (a short form and its cw1, another leaf, an older ck1), but a ck1
    that does not verify for this mint names nothing a wallet should hold.
    Anything that is no spend at all still has to match as text, as it
    always did.
    """
    if a.strip().lower() == b.strip().lower():
        return True
    spend_a = verify_spend(a.strip().lower(), note_url)
    spend_b = verify_spend(b.strip().lower(), note_url)
    return (
        spend_a is not None
        and spend_b is not None
        and spend_a.output_key == spend_b.output_key
    )


def note_info_request(url: str, policy: Policy = DEFAULT_POLICY) -> Request:
    """LUD-03 step one. Never burns, rotates or alters the note.

    The certificate (``c``, or legacy ``sig``) is stripped before the request:
    it is only meaningful to a holder inspecting the note locally, since the SERVICE already knows what it
    signed. ``k1`` and ``amount`` are left as they are.
    """
    parts = urlparse(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in ("c", "sig")]
    request_url = urlunparse(parts._replace(query=urlencode(query)))
    queried = note_k1(url)

    def parse(body: Any) -> WithdrawRequestInfo:
        try:
            _reject_error(body)
        except ServiceRejected as err:
            raise classify_note_error(err.reason) from None
        if not isinstance(body, dict) or body.get("tag") != "withdrawRequest":
            raise ProtocolError("Not a withdrawRequest (unexpected response).")
        callback = body.get("callback")
        k1 = body.get("k1")
        if not isinstance(callback, str) or not isinstance(k1, str):
            raise ProtocolError("Not a withdrawRequest (unexpected response).")
        maximum, minimum = _withdraw_amounts(body)
        # Spec MUST: the response's k1 is the echoed spend itself, never a
        # derived or opaque id. A SERVICE returning something else for the k1
        # it was queried with is non-compliant - or the note was rotated by
        # somebody else, which matters more. "Something else" means another
        # note, not another spelling of this one: see _same_note.
        if queried and not _same_note(k1, queried, url):
            raise ProtocolError(
                "The service echoed back a different k1 than was queried - the "
                "note may have been redeemed elsewhere, or the service isn't "
                "spec-compliant."
            )
        mint_pubkey = body.get("mintPubkey")
        # Separate from the shape check above, and separately worded: this
        # response IS a withdrawRequest, it just describes a note nobody can
        # check offline. Saying "not a withdrawRequest" would send a caller
        # after the wrong fault.
        if policy.require_mint_pubkey and not is_compressed_pubkey(mint_pubkey):
            raise ProtocolError(
                "This service publishes no mintPubkey, so its notes cannot be "
                "verified offline (LUD-25 requires one)."
                if mint_pubkey is None
                else "This service published a mintPubkey that is not a "
                "33-byte compressed secp256k1 key."
            )
        return WithdrawRequestInfo(
            callback=callback,
            k1=k1.lower(),
            max_withdrawable=maximum,
            min_withdrawable=minimum,
            default_description=body.get("defaultDescription"),
            mint_pubkey=mint_pubkey.strip().lower()
            if isinstance(mint_pubkey, str)
            else None,
            signature=_optional_signature(body),
        )

    return Request(url=request_url, parse=parse)


def note_info_by_hash_request(
    withdraw_link: str, h: str, policy: Policy = DEFAULT_POLICY
) -> Request:
    """The informational GET for a note named by its public name, a ``cp1``
    or a bearer note's hex ``h``, so nothing spendable goes on the wire
    (LUD-25, "Checking a note without exposing it").

    What a restore walk uses: a walk queries a whole gap window of indices the
    wallet has not minted into yet, and asking by secret would publish exactly
    the secrets it is about to mint under.

    A rejection means nothing on its own. An unknown note is answered as an
    unknown ``k1`` is, and so is a note that was burned, so only a positive
    answer is evidence.

    Either spelling goes as ``p``: see
    :func:`~lnurlcash_kit.note.build_note_info_url_by_hash`, and
    :func:`~lnurlcash_kit.recoverable.note_lookup_of` for the right value to
    pass for any note.

    Differs from :func:`note_info_request` in exactly two places, both because
    there was no secret in the request: ``k1`` is not required in the response,
    and there is no echo to check. The shape, and ``mintPubkey`` under the
    same ``require_mint_pubkey``, are enforced identically - a mint nobody can
    verify against is no more acceptable when its note was looked up
    privately.
    """
    from .note import build_note_info_url_by_hash

    request_url = build_note_info_url_by_hash(withdraw_link, h)

    def parse(body: Any) -> NoteInfoByHash:
        try:
            _reject_error(body)
        except ServiceRejected as err:
            raise classify_note_error(err.reason) from None
        if not isinstance(body, dict) or body.get("tag") != "withdrawRequest":
            raise ProtocolError("Not a withdrawRequest (unexpected response).")
        callback = body.get("callback")
        if not isinstance(callback, str):
            raise ProtocolError("Not a withdrawRequest (unexpected response).")
        maximum, minimum = _withdraw_amounts(body)
        mint_pubkey = body.get("mintPubkey")
        if policy.require_mint_pubkey and not is_compressed_pubkey(mint_pubkey):
            raise ProtocolError(
                "This service publishes no mintPubkey, so its notes cannot be "
                "verified offline (LUD-25 requires one)."
                if mint_pubkey is None
                else "This service published a mintPubkey that is not a "
                "33-byte compressed secp256k1 key."
            )
        return NoteInfoByHash(
            callback=callback,
            max_withdrawable=maximum,
            min_withdrawable=minimum,
            default_description=body.get("defaultDescription"),
            mint_pubkey=mint_pubkey.strip().lower()
            if isinstance(mint_pubkey, str)
            else None,
            signature=_optional_signature(body),
        )

    return Request(url=request_url, parse=parse)


def mint_address_request(url: str) -> Request:
    """LUD-25 mint address (experimental, optional). Best-effort discovery:
    most SERVICEs will not have it, and a rejection means "no extra
    information", not a failure."""

    def parse(body: Any) -> MintAddressInfo:
        _reject_error(body)
        if (
            not isinstance(body, dict)
            or body.get("tag") != "withdrawRequest"
            or not isinstance(body.get("callback"), str)
            or not isinstance(body.get("payLink"), str)
            or not isinstance(body.get("maxWithdrawable"), int)
        ):
            raise ProtocolError("Not a mint address response (unexpected shape).")
        return MintAddressInfo(
            callback=body["callback"],
            pay_link=body["payLink"],
            max_withdrawable=body["maxWithdrawable"],
            min_withdrawable=body.get("minWithdrawable", 0) or 0,
            node_pubkey=body.get("mintPubkey"),
            node_alias=body.get("nodeAlias"),
            node_uri=body.get("nodeUri"),
            node_color=body.get("nodeColor"),
            node_capacity_msat=_optional_int(body.get("nodeCapacity")),
            node_num_channels=_optional_int(body.get("nodeNumChannels")),
            node_num_peers=_optional_int(body.get("nodeNumPeers")),
            node_uris=_optional_str_tuple(body.get("nodeUris")),
            sunset_date=_optional_iso_date(body.get("sunsetDate")),
            outstanding_notes_msat=_optional_int(body.get("outstandingNotesMsat")),
        )

    return Request(url=url, parse=parse)


# ---- the mutating callback ----
#
# Every ``k1`` here may be any spend: a ck1, a cw1, or a bearer preimage. The
# SERVICE tells them apart by shape, so all pass through untouched, and one
# merge may mix them. Every output may be a bearer ``h`` or a cp1: see
# _output_param.


def _parse_success(body: Any) -> dict:
    try:
        _reject_error(body)
    except ServiceRejected as err:
        # a k1 already mid-melt rejects every other callback naming it with
        # this exact reason string, verbatim per spec
        if err.reason == "pending":
            raise NotePending(err.reason) from None
        raise classify_note_error(err.reason) from None
    if not isinstance(body, dict) or body.get("status") != "OK":
        raise AmbiguousMint(
            "The service did not confirm the operation - it may still have been applied."
        )
    return body


def _names_cp1(output: str) -> bool:
    """Whether an output was named by a ``cp1`` rather than a bearer ``h``,
    which is what decides the certificate it is owed."""
    return is_cp1(output.strip().lower())


def _require_signature(
    value: Any, policy: Policy, what: str, output: str
) -> str | None:
    """What a mutation owes for each note it mints, by the kind of note.

    ``output`` is the ``p1`` (or ``p2``) the mutation named. An output named
    by ``cp1`` is owed its ``cs1``: offline verification is the whole reason
    to name a note that way, so no policy waives it. One named by a bearer
    ``h`` is refused without a certificate only when ``require_signatures``
    asks. A certificate that is present is passed on as sent, never checked
    here: :func:`~lnurlcash_kit.signature.verify_note_signature` is the
    check.

    The mutation has already landed by the time this is called - ``status`` was
    OK - so the exception has to carry the caller's secrets out with it, or
    enforcing the spec becomes the thing that loses the money. ``new_secrets``
    is filled in by the client, which is what holds them. It stays empty after
    a ``*_with_hash`` call, whose caller supplied the output and never gave
    this library its secret.
    """
    if isinstance(value, str) and value:
        return value
    if _names_cp1(output):
        raise UnverifiableNote(
            f"The service confirmed the {what} to a cp1 output but returned no "
            "cs1 certificate, so the note it just minted cannot be verified "
            "offline. The note exists - keep the key."
        )
    if not policy.require_signatures:
        return None
    raise UnverifiableNote(
        f"The service confirmed the {what} but returned no certificate, so the "
        "note it just minted cannot be verified offline. The note exists - "
        "keep the secret."
    )


def _callback(callback: str, params: list[tuple[str, str]]) -> str:
    if not is_allowed_service_url(callback):
        raise RequestRefused("The service provided an invalid callback URL.")
    if not any(key == "k1" for key, _ in params):
        # Nothing to operate on. Worth refusing here rather than letting it
        # become a callback with no k1, whose meaning is entirely up to the
        # SERVICE - and which, read generously, could burn something the
        # caller never named.
        raise RequestRefused(
            "At least one k1 is required - there is no note to operate on."
        )
    return _with_params(callback, params)


def melt_request(callback: str, k1: str, pr: str) -> Request:
    """Burn a single note; the SERVICE pays ``pr`` of exactly its value. Merge
    several notes first to melt them together - LUD-25 dropped multi-k1 melt.

    ``{"status":"OK"}`` means the payment is IN FLIGHT, not that the note is
    spent. The SERVICE pays asynchronously and only finalises the burn once
    the payment settles, restoring the note if it fails - so a melt failure is
    never reported through this call, only observed as the note becoming
    spendable again.
    """
    url = _callback(callback, [("k1", k1), ("pr", pr.strip())])

    def parse(body: Any) -> MeltResult:
        ok = _parse_success(body)
        return MeltResult(
            pr=ok.get("pr") if isinstance(ok.get("pr"), str) else None,
            verify=ok.get("verify") if isinstance(ok.get("verify"), str) else None,
        )

    return Request(url=url, parse=parse)


def _output_param(value: str, which: int) -> tuple[str, str]:
    """An output goes as ``p1``, or ``p2`` for a split's change, as LUD-25
    spells them, whether it is a cp1 or a bearer note's hex ``h`` (its cp1
    short form). Mints from before the rename also read ``h`` and ``h2``, but
    every current one reads ``p1`` and ``p2`` for both. The value itself goes
    out as given, so a retry is byte-identical to the request it repeats.
    """
    return (f"p{which}", value)


def rotate_request_with_hash(
    callback: str, k1: str, h: str, policy: Policy = DEFAULT_POLICY
) -> Request:
    """Rotate ``k1`` into an output the caller names: a bearer note's hex
    ``h``, or a ``cp1``.

    An output named by ``cp1`` that comes back without its ``cs1`` raises
    :class:`~lnurlcash_kit.errors.UnverifiableNote` whatever the policy says.
    One named by a bearer ``h`` returns ``signature`` None from a mint with
    no signer, unless the policy's ``require_signatures`` demands one.
    """
    url = _callback(callback, [("k1", k1), _output_param(h, 1)])

    def parse(body: Any) -> MutationResult:
        ok = _parse_success(body)
        return MutationResult(
            signature=_require_signature(_certificate_field(ok, "c", "sig"), policy, "rotate", h)
        )

    return Request(url=url, parse=parse, replayable=True)


def split_request_with_hash(
    callback: str,
    k1s: list[str],
    amount_msat: int,
    h: str,
    h2: str,
    policy: Policy = DEFAULT_POLICY,
) -> Request:
    """Split into ``amount_msat`` at ``h`` and the change at ``h2``, each a
    bearer ``h`` or a ``cp1``. Each output is owed what its naming is owed,
    exactly as in :func:`rotate_request_with_hash`: a ``cp1`` change without
    ``c2`` raises, a bearer change without one is taken as it is."""
    url = _callback(
        callback,
        [("k1", k1) for k1 in k1s]
        + [("amount", str(amount_msat)), _output_param(h, 1), _output_param(h2, 2)],
    )

    def parse(body: Any) -> MutationResult:
        ok = _parse_success(body)
        # Both outputs of a split are notes, and each is owed what its kind
        # is owed: a cp1 change is no lesser note than a cp1 first output.
        # Checked in output order so the message names the one missing.
        return MutationResult(
            signature=_require_signature(_certificate_field(ok, "c", "sig"), policy, "split", h),
            change_signature=_require_signature(
                _certificate_field(ok, "c2", "sig2"), policy, "split's change", h2
            ),
        )

    return Request(url=url, parse=parse, replayable=True)


def merge_request_with_hash(
    callback: str, k1s: list[str], h: str, policy: Policy = DEFAULT_POLICY
) -> Request:
    url = _callback(callback, [("k1", k1) for k1 in k1s] + [_output_param(h, 1)])

    def parse(body: Any) -> MutationResult:
        ok = _parse_success(body)
        return MutationResult(
            signature=_require_signature(_certificate_field(ok, "c", "sig"), policy, "merge", h)
        )

    return Request(url=url, parse=parse, replayable=True)


# ---- the generating variants ----
#
# Per LUD-25 the WALLET generates every resulting note itself and discloses
# only its public name: here a bearer note, whose preimage is drawn fresh and
# whose h goes out as p1 or p2. The SERVICE never sees, generates or persists
# the preimage, which is what closes the prior-holder exposure a
# SERVICE-generated replacement would otherwise reopen on every single rotate.
#
# The SERVICE certifies these bearer notes over hex(Q) when it has a signer;
# a key-path note is minted through the *_with_hash calls, naming its cp1.


def rotate_request(
    callback: str,
    k1: str,
    rng: Callable[[], str] = generate_note_secret,
    policy: Policy = DEFAULT_POLICY,
) -> Request:
    fresh = rng()
    inner = rotate_request_with_hash(callback, k1, hash_k1(fresh), policy)

    def parse(body: Any) -> RotateResult:
        result = inner.parse(body)
        return RotateResult(k1=fresh, signature=result.signature)

    return Request(url=inner.url, parse=parse, new_secrets=[fresh], replayable=True)


def split_request(
    callback: str,
    k1s: list[str],
    amount_msat: int,
    rng: Callable[[], str] = generate_note_secret,
    policy: Policy = DEFAULT_POLICY,
) -> Request:
    fresh = rng()
    change = rng()
    inner = split_request_with_hash(
        callback, k1s, amount_msat, hash_k1(fresh), hash_k1(change), policy
    )

    def parse(body: Any) -> SplitResult:
        result = inner.parse(body)
        return SplitResult(
            k1=fresh,
            change=change,
            signature=result.signature,
            change_signature=result.change_signature,
        )

    return Request(
        url=inner.url, parse=parse, new_secrets=[fresh, change], replayable=True
    )


def merge_request(
    callback: str,
    k1s: list[str],
    rng: Callable[[], str] = generate_note_secret,
    policy: Policy = DEFAULT_POLICY,
) -> Request:
    fresh = rng()
    inner = merge_request_with_hash(callback, k1s, hash_k1(fresh), policy)

    def parse(body: Any) -> RotateResult:
        result = inner.parse(body)
        return RotateResult(k1=fresh, signature=result.signature)

    return Request(url=inner.url, parse=parse, new_secrets=[fresh], replayable=True)


# ---- minting ----


def pay_request_request(url: str) -> Request:
    def parse(body: Any) -> PayRequestInfo:
        _reject_error(body)
        if (
            not isinstance(body, dict)
            or body.get("tag") != "payRequest"
            or not isinstance(body.get("callback"), str)
        ):
            raise ProtocolError("Not a payRequest (unexpected response).")
        metadata = body.get("metadata")
        # A withdrawLink that is present but not a string is a broken mint,
        # not a mint without one. Reading it as absent would send the caller
        # down the well-known fallback and quietly mint against the wrong
        # endpoint.
        withdraw_link = body.get("withdrawLink")
        if withdraw_link is not None and not isinstance(withdraw_link, str):
            raise ProtocolError("The mint's payRequest has an invalid withdrawLink.")
        comment_allowed = body.get("commentAllowed")
        if not isinstance(comment_allowed, int) or isinstance(comment_allowed, bool):
            comment_allowed = None
        info = PayRequestInfo(
            callback=body["callback"],
            min_sendable=body.get("minSendable", 0),
            max_sendable=body.get("maxSendable", 0),
            metadata=metadata if isinstance(metadata, str) else "",
            withdraw_link=withdraw_link,
            mint_pubkey=body.get("mintPubkey"),
            mint_fee=parse_mint_fee(metadata) if isinstance(metadata, str) else None,
            comment_allowed=comment_allowed,
            mint_to_hash=body.get("mintToHash") is True,
        )
        # LUD-25: minting is comment-bound. A payRequest that advertises a
        # withdrawLink but no room for the 64-character commitment is offering
        # something it cannot deliver, and the failure would otherwise land
        # after the caller had already paid.
        if info.withdraw_link is not None and not info.names_mint_output():
            raise ProtocolError(
                "This mint offers no room for the required output commitment "
                "- it cannot mint."
            )
        return info

    return Request(url=url, parse=parse)


def invoice_request(pay_callback: str, amount_msat: int) -> Request:
    """A plain LUD-06 invoice request.

    Correct for paying an ordinary Lightning address; it mints nothing,
    because it names no output. To mint, use :func:`mint_invoice_request`.
    """
    url = _with_params(pay_callback, [("amount", str(amount_msat))])

    def parse(body: Any) -> InvoiceResult:
        _reject_error(body)
        if not isinstance(body, dict) or not isinstance(body.get("pr"), str):
            raise ProtocolError("The service did not return an invoice.")
        # A SERVICE answering an amount request with an invoice for a
        # DIFFERENT amount is broken or hostile. An amountless invoice passes
        # through: there is nothing to check it against here.
        invoiced = decode_bolt11_amount_msat(body["pr"])
        if invoiced is not None and invoiced != amount_msat:
            raise ProtocolError(
                f"The service returned an invoice for {invoiced} msat, "
                f"not the {amount_msat} requested."
            )
        return InvoiceResult(
            pr=body["pr"],
            verify=body.get("verify") if isinstance(body.get("verify"), str) else None,
            disposable=body.get("disposable") is not False,
        )

    return Request(url=url, parse=parse)


def mint_invoice_request_with_hash(
    pay_callback: str, amount_msat: int, h: str
) -> Request:
    """Ask for a mint invoice, naming the note it will credit: a bearer
    note's ``h = sha256(preimage)`` for a preimage only the WALLET holds, or a
    ``cp1``.

    LUD-25 carries the name as a mandatory LUD-12 ``comment``; for a hex
    ``h``, the ``h`` parameter repeats the identical value for SERVICEs that
    took the parameter form first. It is never an alternative to the comment.

    The SERVICE learns a public name and nothing else, so the payment
    preimage is settlement proof only - it can never redeem the note. That is
    the whole point: a payment preimage propagates to every routing node that
    forwards the payment, and a note keyed by one is a note they can all
    spend.

    A ``cp1`` goes as the comment alone: the ``h`` parameter is a hash-only
    extension, and a mint may refuse a key under it. One whose key is not a
    curve point is refused here, before anything is paid into a note nobody
    could ever spend.
    """
    # lowercase for the same reason a note's k1 is normalised: it is bytes,
    # not text, and a SERVICE storing notes under what it was given should be
    # given one spelling of it
    h = h.strip().lower()
    if is_cp1(h):
        params = [("amount", str(amount_msat)), ("comment", h)]
    elif is_preimage(h):
        params = [("amount", str(amount_msat)), ("comment", h), ("h", h)]
    else:
        # Refused here rather than sent, so a WALLET never pays for a quote
        # the SERVICE was always going to reject.
        raise RequestRefused(
            "An output must be a bearer note's 32-byte hex h or a cp1 naming a "
            "curve point - no invoice was requested."
        )
    # The response shape is an ordinary LUD-06 invoice; reuse its parser
    # rather than restating it.
    inner = invoice_request(pay_callback, amount_msat)
    return Request(url=_with_params(pay_callback, params), parse=inner.parse)


def mint_invoice_request(
    pay_callback: str, amount_msat: int, mint_secret: str
) -> Request:
    """:func:`mint_invoice_request_with_hash`, from the secret itself.

    The secret comes back on :attr:`Request.new_secrets`. **Persist it before
    paying the invoice this returns.** Paying for a note and then losing its
    secret is the one way the comment-bound scheme is worse than the preimage
    one it replaced, and persisting first removes it entirely.
    """
    # Checked before hashing, so a malformed secret is RequestRefused - the
    # caller's own input, nothing sent - rather than an error that accuses the
    # SERVICE of a broken response it never sent.
    if not is_preimage(mint_secret):
        raise RequestRefused(
            "A note secret must be 32 bytes of hex - no invoice was requested."
        )
    inner = mint_invoice_request_with_hash(
        pay_callback, amount_msat, hash_k1(mint_secret)
    )
    return Request(url=inner.url, parse=inner.parse, new_secrets=[mint_secret])


def verify_request(verify_url: str) -> Request:
    """LUD-21, to learn whether a mint or melt has settled.

    Under current LUD-25 this is unconditionally safe to call and its answer
    unconditionally safe to disclose: minting is comment-bound, so the
    preimage a settled invoice reveals is settlement proof and never the
    note's credential. (It was not always so. An earlier draft keyed the note
    by the payment preimage, which made this endpoint hand out the money; that
    fallback is gone.)"""

    def parse(body: Any) -> VerifyResult:
        _reject_error(body)
        if (
            not isinstance(body, dict)
            or not isinstance(body.get("settled"), bool)
            or not isinstance(body.get("pr"), str)
        ):
            raise ProtocolError("The service returned an unexpected verify response.")
        preimage = body.get("preimage")
        return VerifyResult(
            settled=body["settled"],
            preimage=preimage if isinstance(preimage, str) else None,
            pr=body["pr"],
        )

    return Request(url=verify_url, parse=parse)
