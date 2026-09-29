"""Every assertion here comes from lnurlcash-conformance. Nothing in this file
states what the protocol is - the vectors do, and this suite only binds them
to the library's functions."""

from __future__ import annotations

import hashlib
import unicodedata
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from coincurve import PrivateKey, PublicKey, PublicKeyXOnly

from conftest import load_vectors
from lnurlcash_kit.protocol import (
    invoice_request,
    mint_invoice_request,
    mint_invoice_request_with_hash,
    pay_request_request,
    verify_request,
)
from lnurlcash_kit import (
    NOSTR_CASH_SEED_LABEL,
    AmbiguousMint,
    Certification,
    Cs1,
    Cx1,
    LnurlcashClient,
    LnurlcashError,
    MintFee,
    NotePending,
    NoteSpent,
    NoteUnknown,
    ServiceRejected,
    UnverifiableNote,
    address_proof_digest,
    address_proof_message,
    cash_domain_indices,
    cash_node_from_hex,
    cash_node_to_cx1,
    cash_node_to_hex,
    decode_any_cs1,
    decode_ck1,
    decode_cp1,
    decode_cs1,
    decode_cs1_with_amount,
    decode_cx1,
    derive_cash_address_node,
    derive_cash_child,
    derive_cash_domain_node,
    derive_cash_root,
    derive_note_pubkey,
    derive_note_root,
    derive_note_secret,
    derive_note_secret_key,
    derive_nostr_address_node,
    derive_nostr_cash_seed,
    encode_ck1,
    encode_cp1,
    encode_cs1,
    encode_cs1_with_amount,
    encode_cx1,
    is_any_cs1,
    is_ck1,
    is_cp1,
    is_cs1,
    is_cs1_with_amount,
    is_cx1,
    note_id_of,
    note_lookup_of,
    note_signature_digest_for_hash,
    note_signature_message_for_hash,
    recover_note_ownership_pubkey,
    sign_note_ownership,
    sign_address_proof,
    verify_note_signature_for_key,
    verify_note_signature_hash,
    verify_note_url,
    verify_spend,
    bearer_cw1,
    bearer_leaf,
    bearer_note,
    bearer_note_id,
    key_path_sighash,
    spend_domain_of,
    spend_prevout,
    spend_sig_msg,
    tap_leaf_hash,
    NUMS_KEY,
    hash_k1,
    ProtocolError,
    RequestRefused,
    apply_mint_fee,
    build_note_url,
    decode_bolt11_amount_msat,
    format_fee_percent,
    from_bech32_lnurl,
    gross_up_for_mint_fee,
    is_allowed_service_url,
    is_bolt11_invoice,
    is_preimage,
    lightning_address_username,
    mint_address_url,
    note_declared_amount,
    note_k1,
    note_signature,
    note_signature_digest,
    note_signature_message,
    parse_mint_fee,
    resolve_lnurl_input,
    resolve_mint_input,
    resolve_note_input,
    same_invoice,
    to_bech32_lnurl,
    verify_note_signature,
    with_new_k1,
    without_k1,
)


def _cases(name: str, key: str):
    return load_vectors(name)[key]


def _nested(name: str, key: str, inner: str):
    return load_vectors(name)[key][inner]


# ---- signatures ----


# signature.json predates every note being keyed by Q: each case certifies a
# bearer note over its h, the message a mint used before taproot. That is
# exactly LUD-25's fallback, so a valid case must verify as it and nothing
# more.


@pytest.mark.parametrize("case", _cases("signature.json", "cases"), ids=lambda c: c["name"])
def test_signature_verification(case):
    want = Certification.CERTIFIED_OVER_HASH if case["valid"] else Certification.NOT_CERTIFIED
    got = verify_note_signature(
        case["k1"], "mint.example", case["amountMsat"], case["signature"], case["mintPubkey"]
    )
    assert got is want
    assert bool(got) is case["valid"]
    if is_preimage(case["k1"]):
        h = hash_k1(case["k1"])
        assert (
            verify_note_signature_hash(h, case["amountMsat"], case["signature"], case["mintPubkey"])
            is want
        )


@pytest.mark.parametrize(
    "case",
    [c for c in _cases("signature.json", "cases") if c["message"] is not None],
    ids=lambda c: c["name"],
)
def test_signature_digest_derivation(case):
    # the pre-taproot message, over h
    h = hash_k1(case["k1"])
    assert note_signature_message_for_hash(h, case["amountMsat"]) == case["message"]
    assert note_signature_digest_for_hash(h, case["amountMsat"]).hex() == case["digest"]
    # and the message a current mint signs names the note by hex(Q)
    q = bearer_note_id(h)
    assert note_signature_message(case["k1"], case["amountMsat"]) == f"LNURLcash:{case['amountMsat']}:{q}"
    assert note_signature_digest(case["k1"], case["amountMsat"]) == note_signature_digest_for_hash(
        q, case["amountMsat"]
    )


# ---- response classification ----
#
# responses.json: what each answer to a callback means for the money. `op`
# says which call a case is driven through, and `output` and `change` which
# kind of note the mutation mints, a hash unless the case says cp1. Driven
# through the real client over a mock transport, so a dropped connection, a
# timeout and an unreadable body are graded on the client's own
# classification rather than a restatement of it. Retries are off so one case
# is one request - the replay behaviour has its own tests.

_RESPONSES = "responses.json"
_RESPONSE_CB = "https://mint.example/w/cb"
_RESPONSE_K1 = "a" * 64
# a cp1 has to name a curve point, or no conforming mint would take it
_RESPONSE_OUTPUTS = {
    "hash": "b" * 64,
    "cp1": encode_cp1(PrivateKey(bytes([0x0B]) * 32).public_key_xonly.format()),
}
_RESPONSE_CHANGES = {
    "hash": "c" * 64,
    "cp1": encode_cp1(PrivateKey(bytes([0x0D]) * 32).public_key_xonly.format()),
}
_RESPONSE_OUTCOMES = {
    "pending": NotePending,
    "spent": NoteSpent,
    "unknown": NoteUnknown,
    "ambiguous": AmbiguousMint,
    "unverifiable": UnverifiableNote,
}


def _response_cases() -> list[tuple[dict, str]]:
    """Each case with the call it goes through. A bare "mutation" is any of
    the single-output mutations, so it goes through both of them: a merge owes
    its output exactly what a rotate does."""
    driven = []
    for case in _cases(_RESPONSES, "cases"):
        for via in ("rotate", "merge") if case["op"] == "mutation" else (case["op"],):
            driven.append((case, via))
    return driven


def _answering(case: dict) -> httpx.MockTransport:
    def answer(request: httpx.Request) -> httpx.Response:
        if case.get("transportError"):
            raise httpx.ConnectError("network error", request=request)
        if case.get("timeout"):
            raise httpx.ReadTimeout("timed out", request=request)
        if "bodyRaw" in case:
            return httpx.Response(case["http"], text=case["bodyRaw"])
        return httpx.Response(case["http"], json=case["body"])

    return httpx.MockTransport(answer)


def _drive(case: dict, via: str):
    # a kind this does not know is a vector this suite cannot grade, and
    # reading it as a hash would pass it on no evidence
    output = _RESPONSE_OUTPUTS[case.get("output", "hash")]
    change = _RESPONSE_CHANGES[case.get("change", "hash")]
    with httpx.Client(transport=_answering(case)) as http:
        client = LnurlcashClient(client=http, mutation_retries=0)
        if via == "melt":
            return client.melt_note(_RESPONSE_CB, _RESPONSE_K1, "lnbc210n1pjq")
        if via == "split":
            return client.split_note_with_hash(
                _RESPONSE_CB, [_RESPONSE_K1], 5000, output, change
            )
        if via == "merge":
            return client.merge_notes_with_hash(_RESPONSE_CB, [_RESPONSE_K1], output)
        assert via == "rotate", f"no call for op {via!r}"
        return client.rotate_note_with_hash(_RESPONSE_CB, _RESPONSE_K1, output)


def test_response_vectors_name_every_outcome_this_suite_grades():
    vectors = load_vectors(_RESPONSES)
    expected = {case["expect"] for case in vectors["cases"]}
    assert expected <= set(vectors["outcomes"])
    assert expected <= set(_RESPONSE_OUTCOMES) | {"ok", "error"}
    # the cp1 cases are what this file exists to drive; losing them to a
    # renamed field would pass every hash case and grade nothing
    assert any(case.get("output") == "cp1" for case in vectors["cases"])
    assert any(case.get("change") == "cp1" for case in vectors["cases"])


@pytest.mark.parametrize(
    "case,via",
    _response_cases(),
    ids=lambda v: v if isinstance(v, str) else f"{v['expect']}: {v['name']}",
)
def test_response_classification(case, via):
    if case["expect"] == "ok":
        result = _drive(case, via)
        if via == "melt":
            return
        # Absent means none: the response fixture models no-signer mode rather
        # than something this suite merely declined to check.
        assert result.signature == case.get("signature")
        if via == "split":
            assert result.change_signature == case.get("changeSignature")
        return
    with pytest.raises(LnurlcashError) as raised:
        _drive(case, via)
    if case["expect"] == "error":
        # a definitive refusal for some other reason must not be mistaken for
        # one of the note-specific outcomes a holder acts on
        assert isinstance(raised.value, ServiceRejected)
        assert not isinstance(raised.value, (NotePending, NoteSpent, NoteUnknown))
    else:
        assert isinstance(raised.value, _RESPONSE_OUTCOMES[case["expect"]])


# ---- the informational GET ----
#
# withdraw-info.json: what a note's informational GET may answer. Driven
# through the real client over a mock transport, the way responses.json is,
# for the vector's own queried URL, so the request the client builds is graded
# alongside how it reads the answer: sig never reaches the SERVICE, and k1
# goes out exactly as the note carried it.

_WITHDRAW_INFO = "withdraw-info.json"


def _drive_note_info(case: dict) -> tuple[object, dict[str, list[str]]]:
    """What the client made of the case's body, a result or the error it
    raised, and the query it sent to get it."""
    queried = load_vectors(_WITHDRAW_INFO)["queriedUrl"]
    sent: list[httpx.Request] = []

    def answer(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json=case["body"])

    with httpx.Client(transport=httpx.MockTransport(answer)) as http:
        try:
            outcome: object = LnurlcashClient(client=http).fetch_note_info(queried)
        except LnurlcashError as err:
            outcome = err
    assert len(sent) == 1, "one informational GET, and nothing else"
    return outcome, parse_qs(sent[0].url.query.decode(), keep_blank_values=True)


def _assert_sent_as_queried(query: dict[str, list[str]]) -> None:
    vectors = load_vectors(_WITHDRAW_INFO)
    queried = parse_qs(urlparse(vectors["queriedUrl"]).query, keep_blank_values=True)
    for key in vectors["requestMustNotSend"]:
        assert key not in query, f"sent {key}, which the SERVICE must never see"
    for key in vectors["requestMustSendUnchanged"]:
        assert query.get(key) == queried[key], f"{key} did not go out as queried"


def test_withdraw_info_vectors_are_the_shape_this_suite_grades():
    # a field this suite does not read is one nobody is grading
    vectors = load_vectors(_WITHDRAW_INFO)
    assert vectors["version"] == 1
    assert set(vectors) == {
        "version",
        "spec",
        "description",
        "queriedUrl",
        "requestMustNotSend",
        "requestMustSendUnchanged",
        "accepted",
        "rejected",
    }
    for case in vectors["accepted"]:
        assert set(case) <= {"name", "body", "maxWithdrawable", "why"}
        assert "maxWithdrawable" in case
    for case in vectors["rejected"]:
        assert set(case) <= {"name", "body", "why"}


@pytest.mark.parametrize(
    "case", _cases(_WITHDRAW_INFO, "accepted"), ids=lambda c: c["name"]
)
def test_note_info_accepted(case):
    info, sent = _drive_note_info(case)
    _assert_sent_as_queried(sent)
    assert not isinstance(info, LnurlcashError), f"refused: {info} ({case.get('why')})"
    assert type(info.max_withdrawable) is int
    assert info.max_withdrawable == case["maxWithdrawable"]


@pytest.mark.parametrize(
    "case", _cases(_WITHDRAW_INFO, "rejected"), ids=lambda c: c["name"]
)
def test_note_info_rejected(case):
    outcome, sent = _drive_note_info(case)
    _assert_sent_as_queried(sent)
    assert isinstance(outcome, ProtocolError), (
        f"got {outcome!r}, want a ProtocolError ({case.get('why')})"
    )


# ---- bech32 ----


@pytest.mark.parametrize("case", _cases("bech32.json", "encode"))
def test_bech32_round_trip(case):
    assert to_bech32_lnurl(case["url"]) == case["lnurl"]
    assert from_bech32_lnurl(case["lnurl"]) == case["url"]


@pytest.mark.parametrize("case", _cases("bech32.json", "decodeInvalid"))
def test_bech32_rejects_invalid(case):
    assert from_bech32_lnurl(case["input"]) is None


def test_bech32_is_case_insensitive():
    case = load_vectors("bech32.json")["caseInsensitive"]
    assert from_bech32_lnurl(case["lower"]) == case["url"]
    assert from_bech32_lnurl(case["upper"]) == case["url"]


# ---- url admission ----


@pytest.mark.parametrize("url", _cases("url-admission.json", "allowed"))
def test_url_allowed(url):
    assert is_allowed_service_url(url) is True


@pytest.mark.parametrize("case", _cases("url-admission.json", "rejected"), ids=lambda c: c["why"])
def test_url_rejected(case):
    assert is_allowed_service_url(case["url"]) is False


# ---- input resolution ----


@pytest.mark.parametrize("case", _cases("input-resolution.json", "lnurl"))
def test_resolve_lnurl_input(case):
    assert resolve_lnurl_input(case["input"]) == case["expect"]


@pytest.mark.parametrize("case", _cases("input-resolution.json", "mint"))
def test_resolve_mint_input(case):
    assert resolve_mint_input(case["input"]) == case["expect"]


@pytest.mark.parametrize("case", _cases("input-resolution.json", "note"))
def test_resolve_note_input(case):
    assert resolve_note_input(case["input"]) == case["expect"]


@pytest.mark.parametrize("case", _cases("input-resolution.json", "mintAddressUrl"))
def test_mint_address_url(case):
    assert mint_address_url(case["payUrl"]) == case["expect"]


@pytest.mark.parametrize(
    "case", _cases("input-resolution.json", "lightningAddressUsername")
)
def test_lightning_address_username(case):
    assert lightning_address_username(case["payUrl"]) == case["expect"]


# ---- note urls ----


@pytest.mark.parametrize("case", _cases("note-url.json", "parse"))
def test_note_url_parse(case):
    assert note_k1(case["url"]) == case["k1"]
    assert note_declared_amount(case["url"]) == case["declaredAmountMsat"]
    assert note_signature(case["url"]) == case["signature"]


@pytest.mark.parametrize("case", _cases("note-url.json", "build"))
def test_note_url_build(case):
    assert build_note_url(case["withdrawLink"], case["k1"], case["amountMsat"]) == case["expect"]


@pytest.mark.parametrize("case", _cases("note-url.json", "withNewK1"))
def test_with_new_k1(case):
    assert (
        with_new_k1(case["url"], case["k1"], case["amountMsat"], case["signature"])
        == case["expect"]
    )


@pytest.mark.parametrize("case", _cases("note-url.json", "withoutK1"))
def test_without_k1(case):
    assert without_k1(case["url"], case["amountMsat"], case["signature"]) == case["expect"]


# ---- fees ----


def _fee(raw: dict) -> MintFee:
    return MintFee(base_fee_msat=raw["baseFeeMsat"], fee_ppm=raw["feePpm"])


@pytest.mark.parametrize("case", _cases("fees.json", "parse"))
def test_parse_mint_fee(case):
    parsed = parse_mint_fee(case["metadata"])
    if case["expect"] is None:
        assert parsed is None
    else:
        assert parsed == _fee(case["expect"])


@pytest.mark.parametrize("case", _cases("fees.json", "apply"))
def test_apply_mint_fee(case):
    assert apply_mint_fee(case["grossMsat"], _fee(case["fee"])) == case["expect"]


@pytest.mark.parametrize("case", _cases("fees.json", "grossUp"))
def test_gross_up_for_mint_fee(case):
    assert gross_up_for_mint_fee(case["netMsat"], _fee(case["fee"])) == case["expect"]


def test_gross_up_is_always_the_true_minimum():
    spec = load_vectors("fees.json")["grossUpRoundTrip"]
    for raw in spec["fees"]:
        fee = _fee(raw)
        for net in spec["netAmountsMsat"]:
            gross = gross_up_for_mint_fee(net, fee)
            assert apply_mint_fee(gross, fee) == net
            assert apply_mint_fee(gross - 1, fee) < net


@pytest.mark.parametrize("case", _cases("fees.json", "formatPercent"))
def test_format_fee_percent(case):
    assert format_fee_percent(case["ppm"]) == case["expect"]


# ---- bolt11 ----


@pytest.mark.parametrize("case", _cases("bolt11.json", "decodeAmountMsat"))
def test_decode_bolt11_amount(case):
    assert decode_bolt11_amount_msat(case["pr"]) == case["expect"]


@pytest.mark.parametrize("case", _cases("bolt11.json", "isInvoice"))
def test_is_bolt11_invoice(case):
    assert is_bolt11_invoice(case["pr"]) is case["expect"]


@pytest.mark.parametrize("case", _cases("bolt11.json", "sameInvoice"))
def test_same_invoice(case):
    assert same_invoice(case["a"], case["b"]) is case["expect"]


@pytest.mark.parametrize("case", _cases("bolt11.json", "isPreimage"))
def test_is_preimage(case):
    assert is_preimage(case["value"]) is case["expect"]


# ---- LUD-25 minting ----
#
# This is the suite that would have caught the library sitting on the deleted
# preimage-keyed model for a month: nothing here states an opinion of its own,
# so a draft change lands as a red test rather than as a silent divergence
# discovered by a wallet that could not mint.

_MINT_CALLBACK = "https://mint.example/p/cb"


@pytest.mark.parametrize(
    "case", _cases("pay-request.json", "accepted"), ids=lambda c: c["name"]
)
def test_pay_request_accepted(case):
    info = pay_request_request("https://mint.example/p").parse(case["body"])
    assert info.withdraw_link == case.get("withdrawLink")
    assert info.comment_allowed == case.get("commentAllowed")
    expected_fee = case.get("mintFee")
    if expected_fee is None:
        assert info.mint_fee is None
    else:
        assert info.mint_fee == MintFee(
            base_fee_msat=expected_fee["baseFeeMsat"], fee_ppm=expected_fee["feePpm"]
        )
    # A payRequest is only a mint if it can carry the commitment, and a mint is
    # only a mint if it advertises where the note will live.
    assert info.names_mint_output() is (info.withdraw_link is not None)


@pytest.mark.parametrize(
    "case", _cases("pay-request.json", "rejected"), ids=lambda c: c["name"]
)
def test_pay_request_rejected(case):
    with pytest.raises(ProtocolError):
        pay_request_request("https://mint.example/p").parse(case["body"])


@pytest.mark.parametrize(
    "case",
    _nested("pay-request.json", "mintCallback", "accepted"),
    ids=lambda c: c["name"],
)
def test_mint_callback_names_the_note(case):
    request = mint_invoice_request_with_hash(
        _MINT_CALLBACK, case["amountMsat"], case["comment"]
    )
    # LUD-25 carries the commitment as a mandatory LUD-12 comment; h repeats it
    # for the additive ForgeSworn profile.
    assert f"comment={case['comment']}" in request.url
    assert f"h={case['comment']}" in request.url
    assert f"amount={case['amountMsat']}" in request.url
    assert case["noteId"] == case["comment"]
    assert case["paymentPreimageIsBearerK1"] is False


@pytest.mark.parametrize(
    "case",
    _nested("pay-request.json", "mintCallback", "rejected"),
    ids=lambda c: c["name"],
)
def test_mint_callback_refuses_an_unnamed_output(case):
    # A null comment is the unnamed mint the draft forbids: this library cannot
    # express one, because the minting builder requires the commitment. A
    # malformed one is refused before anything is sent.
    with pytest.raises(RequestRefused):
        if case["comment"] is None:
            mint_invoice_request(_MINT_CALLBACK, case["amountMsat"], "")
        else:
            mint_invoice_request_with_hash(
                _MINT_CALLBACK, case["amountMsat"], case["comment"]
            )


@pytest.mark.parametrize(
    "case", _nested("pay-request.json", "invoice", "accepted"), ids=lambda c: c["name"]
)
def test_invoice_accepted(case):
    result = invoice_request(_MINT_CALLBACK, case["requestedMsat"]).parse(case["body"])
    assert result.disposable is case["disposable"]
    assert result.verify == case.get("verify")


@pytest.mark.parametrize(
    "case", _nested("pay-request.json", "invoice", "rejected"), ids=lambda c: c["name"]
)
def test_invoice_rejected(case):
    with pytest.raises(ProtocolError):
        invoice_request(_MINT_CALLBACK, case["requestedMsat"]).parse(case["body"])


@pytest.mark.parametrize(
    "case", _nested("pay-request.json", "verify", "accepted"), ids=lambda c: c["name"]
)
def test_verify_accepted(case):
    result = verify_request("https://mint.example/verify/abc").parse(case["body"])
    assert result.settled is case["settled"]
    assert result.preimage == case.get("preimage")


@pytest.mark.parametrize(
    "case", _nested("pay-request.json", "verify", "rejected"), ids=lambda c: c["name"]
)
def test_verify_rejected(case):
    with pytest.raises(ProtocolError):
        verify_request("https://mint.example/verify/abc").parse(case["body"])


# ---- derivation ----
#
# The two schemes a wallet may mint under. cash-derivation.json is the one
# LUD-25 specifies and the one a new wallet uses; derivation.json is the
# pre-spec HMAC scheme, kept because notes minted under it are still money.
#
# A disagreement with either file is a wallet that cannot restore what another
# implementation of the same seed phrase minted, which is the whole reason
# these vectors exist rather than each library testing itself.


def test_cash_derivation_scheme_is_the_one_this_library_implements():
    scheme = load_vectors("cash-derivation.json")["scheme"]
    assert scheme["purpose"] == "m/139'"
    # The one thing an implementation can silently get wrong: d1..d4 are raw
    # uint32, hardened only where they happen to land at or above 2^31.
    assert scheme["hardenedByMagnitudeOnly"] is True


def test_cash_derivation_matches_bip32_vector_1():
    # BIP-32's own published vector, so a failure here says CKDpriv is wrong
    # rather than the LUD-25 path above it. The chain alternates hardened and
    # unhardened, which is exactly the pair of legs the domain levels land on.
    steps = load_vectors("cash-derivation.json")["bip32Vector1"]
    node = cash_node_from_hex(steps[0]["node"])
    for step in steps[1:]:
        node = derive_cash_child(node, step["index"])
        assert cash_node_to_hex(node) == step["node"]


@pytest.mark.parametrize(
    "case", _cases("cash-derivation.json", "cases"), ids=lambda c: c["name"]
)
def test_cash_derivation(case):
    seed = bytes.fromhex(case["seedHex"])
    root = derive_cash_root(seed)
    assert cash_node_to_hex(root) == case["cashRoot"]
    assert list(cash_domain_indices(root, case["host"])) == case["domainIndices"]

    domain_node = derive_cash_domain_node(root, case["host"])
    assert cash_node_to_hex(domain_node) == case["domainNode"]


def test_legacy_derivation_scheme():
    assert load_vectors("derivation.json")["scheme"]["rootKey"] == "lnurlcash-note-v1"


@pytest.mark.parametrize("case", _cases("derivation.json", "cases"), ids=lambda c: c["name"])
def test_legacy_derivation(case):
    root = derive_note_root(bytes.fromhex(case["seedHex"]))
    k1 = derive_note_secret(root, case["host"], case["index"])
    assert k1 == case["k1"]
    assert hash_k1(k1) == case["noteId"]


# ---- key-path notes ----
#
# part2.json: notes whose output key is a holder's own key, spent by a ck1
# bound to the mint's domain. Every field of every branch, note and
# certificate is bound to the library here, including verifying each ck1
# against its note key at its domain and recovering each cs1 to the mint's.
# A disagreement is a note one implementation mints and another cannot find,
# or cannot spend.

_PART2 = "part2.json"
_HARDENED = 0x80000000
_PART2_DECODERS = {
    "cp1": decode_cp1,
    "ck1": decode_ck1,
    "cs1": lambda value: (
        certificate.signature
        if (certificate := decode_cs1_with_amount(value)) is not None
        else None
    ),
    "cx1": decode_cx1,
}
_PART2_TESTS = {
    "cp1": is_cp1,
    "ck1": is_ck1,
    "cs1": is_cs1_with_amount,
    "cx1": is_cx1,
}


def _bip39_seed(mnemonic: str) -> bytes:
    """BIP-39's phrase-to-seed step, with no passphrase.

    The library deliberately takes raw seed bytes and never a phrase, which
    keeps a wordlist out of every consumer's environment. But the vectors
    carry the phrase too, so the step that joins the two is graded here rather
    than taken on trust.
    """
    phrase = unicodedata.normalize("NFKD", mnemonic).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", phrase, b"mnemonic", 2048)


def _branch_id(branch: dict) -> str:
    return f"{branch['mnemonic'].split()[0]}/{branch['host']}"


def _part2_notes() -> list[tuple[dict, dict]]:
    return [(b, n) for b in _cases(_PART2, "branches") for n in b["notes"]]


def test_part2_conventions_are_the_ones_this_library_implements():
    conventions = load_vectors(_PART2)["conventions"]
    # the spec text's literal path: the address branch is the domain node
    assert conventions["addressBranch"] == "m/139'/d1/d2/d3/d4"
    assert conventions["hashingKey"] == "m/139'/0"
    assert conventions["spendDomain"].startswith("the host's lowercase hostname")
    assert conventions["ck1Signs"].startswith('tagged_hash("TapSighash", 0x00 || SigMsg)')
    assert conventions["keyPathSignature"].startswith("BIP-340 Schnorr, 64 bytes, all-zero aux_rand")
    assert conventions["ck1Payload"] == "32-byte x-only public key || 64-byte Schnorr signature"
    assert conventions["addressProofMessage"] == "LNURLcash:<register|unregister>:<domain>:<username>"
    assert conventions["addressProofMessageEncoding"].startswith("UTF-8 bytes, sha256-hashed")
    assert conventions["certificateMessage"] == "LNURLcash:<amount_msat>:<hex(pk)>"
    assert conventions["certificateHrp"] == "cs || BOLT11_amount_suffix(amount_msat)"
    assert conventions["indexWidth"].startswith("4 bytes, big-endian")
    # the sighash itself is bound in test_part2_note, by reproducing every
    # vector's sighash and signature


@pytest.mark.parametrize(
    "proof",
    _cases(_PART2, "addressProofs"),
    ids=lambda p: f"{p['action']}/{p['domain']}/{p['username']}",
)
def test_address_proof(proof):
    action, domain, username = proof["action"], proof["domain"], proof["username"]
    # the mint's own domain, however the caller happens to spell it
    for spelling in (domain, domain.upper(), f"https://{domain}/w"):
        assert address_proof_message(action, spelling, username) == proof["message"]
    message = proof["message"]
    digest = address_proof_digest(action, domain, username)
    assert digest.hex() == proof["digest"]
    assert digest == hashlib.sha256(message.encode("utf-8")).digest()
    key = bytes.fromhex(proof["indexZeroSecretKey"])
    signature = sign_address_proof(key, action, domain, username)
    assert signature.hex() == proof["signature"]
    assert PublicKeyXOnly(bytes.fromhex(proof["indexZeroPubkey"])).verify(signature, digest)
    # a proof for one mint is no proof at another
    assert sign_address_proof(key, action, "elsewhere.example", username) != signature


def test_address_proofs_cover_more_than_one_mint():
    assert len({p["domain"] for p in _cases(_PART2, "addressProofs")}) >= 2


def test_address_proof_rejects_unknown_action_and_no_mint():
    with pytest.raises(ProtocolError):
        address_proof_message("delete", "mint.example", "alice")
    with pytest.raises(ProtocolError):
        address_proof_digest("delete", "mint.example", "alice")
    with pytest.raises(ProtocolError):
        address_proof_message("register", "", "alice")


def test_part2_covers_both_branch_parities_and_the_whole_index_range():
    # an odd-parity branch is the only thing that exercises the negation in
    # derive_note_secret_key, and 2^31 and 2^32 - 1 are where an
    # implementation that hardens or narrows the index shows itself
    branches = load_vectors(_PART2)["branches"]
    assert {b["branchParity"] for b in branches} == {"even", "odd"}
    for branch in branches:
        indices = [n["index"] for n in branch["notes"]]
        assert _HARDENED in indices and 0xFFFFFFFF in indices


@pytest.mark.parametrize("branch", _cases(_PART2, "branches"), ids=_branch_id)
def test_part2_branch(branch):
    seed = _bip39_seed(branch["mnemonic"])
    assert seed.hex() == branch["seedHex"]
    root = derive_cash_root(seed)
    assert cash_node_to_hex(root) == branch["cashRoot"]

    # the hashing key is m/139'/0, so the four levels hang off the root itself
    assert list(cash_domain_indices(root, branch["host"])) == branch["domainIndices"]
    # the derivation hashes the host as stored; a spend binds its hostname
    assert spend_domain_of(branch["host"]) == branch["domain"]

    node = derive_cash_address_node(root, branch["host"])
    assert cash_node_to_hex(node) == branch["addressNode"]
    assert cash_node_to_hex(node) == cash_node_to_hex(
        derive_cash_domain_node(root, branch["host"])
    )

    cx1 = cash_node_to_cx1(node)
    assert cx1.pubkey_x_only.hex() == branch["branchPubkey"]
    assert cx1.chain_code.hex() == branch["chainCode"]
    prefix = PrivateKey(node.private_key).public_key.format(compressed=True)[0]
    assert ("even" if prefix == 0x02 else "odd") == branch["branchParity"]
    assert encode_cx1(cx1.pubkey_x_only, cx1.chain_code) == branch["cx1"]
    assert decode_cx1(branch["cx1"]) == cx1
    assert is_cx1(branch["cx1"])


@pytest.mark.parametrize(
    "branch,note",
    _part2_notes(),
    ids=lambda v: _branch_id(v) if "mnemonic" in v else f"#{v['index']}",
)
def test_part2_note(branch, note):
    index = note["index"]
    node = cash_node_from_hex(branch["addressNode"])

    # the watcher's half, from nothing but the cx1
    watched = decode_cx1(branch["cx1"])
    assert watched is not None
    pk = derive_note_pubkey(watched.pubkey_x_only, watched.chain_code, index)
    assert pk.hex() == note["notePubkey"]

    # the holder's half, and that it is the key the watcher derived
    sk = derive_note_secret_key(node.private_key, node.chain_code, index)
    assert sk.hex() == note["noteSecretKey"]
    assert PrivateKey(sk).public_key.format(compressed=True)[1:] == pk

    assert encode_cp1(pk) == note["cp1"]
    assert decode_cp1(note["cp1"]) == pk

    _grade_key_path_note(sk, pk, note, branch["domain"])


def _grade_key_path_note(sk: bytes, pk: bytes, note: dict, domain: str) -> None:
    # the key-path sighash for this note at this mint
    assert key_path_sighash(pk, domain).hex() == note["sighash"]

    # Fixed all-zero BIP-340 auxiliary input, so re-deriving the key
    # reproduces the ck1 byte for byte for seed recovery
    payload = sign_note_ownership(sk, domain)
    assert payload[:32] == pk
    assert payload[32:].hex() == note["keyPathSignature"]
    assert encode_ck1(payload) == note["ck1"]
    assert decode_ck1(note["ck1"]) == payload

    # Verified twice: through the library, and straight off the vector's own
    # sighash, which pins exactly what the library signs over.
    owner = recover_note_ownership_pubkey(payload, domain)
    assert owner is not None and owner.pubkey_x_only == pk and not owner.legacy
    assert PublicKeyXOnly(pk).verify(payload[32:], bytes.fromhex(note["sighash"]))
    verified = verify_spend(note["ck1"], domain)
    assert verified is not None and verified.output_key == pk and not verified.legacy
    # and it is bound to that mint: anywhere else it opens nothing
    assert verify_spend(note["ck1"], "elsewhere." + domain) is None

    assert note_id_of(note["ck1"]) == note["notePubkey"]
    assert note_id_of(note["ck1"].upper()) == note["notePubkey"]
    assert note_lookup_of(note["ck1"]) == note["cp1"]


@pytest.mark.parametrize(
    "cert", _cases(_PART2, "certificates"), ids=lambda c: f"{c['amountMsat']}msat"
)
def test_part2_certificate(cert):
    vectors = load_vectors(_PART2)
    mint = vectors["mint"]
    mint_key = PrivateKey(bytes.fromhex(mint["privateKey"]))
    assert mint_key.public_key.format(compressed=True).hex() == mint["mintPubkey"]

    note_pubkey, amount = cert["notePubkey"], cert["amountMsat"]
    assert note_signature_message_for_hash(note_pubkey, amount) == cert["message"]
    digest = note_signature_digest_for_hash(note_pubkey, amount)
    assert digest.hex() == cert["digest"]

    signature = bytes.fromhex(cert["signature"])
    # the mint's side is as deterministic as the holder's
    assert mint_key.sign_recoverable(digest, hasher=None) == signature
    assert encode_cs1_with_amount(amount, signature) == cert["cs1"]
    assert decode_cs1_with_amount(cert["cs1"]) == Cs1(amount, signature)
    assert is_cs1_with_amount(cert["cs1"])
    assert not is_cs1(cert["cs1"])
    assert decode_any_cs1(cert["cs1"]) == signature
    assert is_any_cs1(cert["cs1"])

    legacy = encode_cs1(signature)
    assert decode_cs1(legacy) == signature
    assert is_cs1(legacy)
    assert decode_cs1_with_amount(legacy) is None
    assert not is_cs1_with_amount(legacy)
    assert decode_any_cs1(legacy) == signature
    assert is_any_cs1(legacy)
    recovered = PublicKey.from_signature_and_message(signature, digest, hasher=None)
    assert recovered.format(compressed=True).hex() == mint["mintPubkey"]

    # a watcher's check, holding only the key, in either spelling
    for spelling in (cert["cs1"], cert["signature"]):
        assert (
            verify_note_signature_for_key(note_pubkey, amount, spelling, mint["mintPubkey"])
            is Certification.CERTIFIED_OVER_Q
        )

    # and a recipient's, holding the ck1 and its mint's domain, offline
    ck1, domain = next(
        (n["ck1"], b["domain"])
        for b in vectors["branches"]
        for n in b["notes"]
        if n["notePubkey"] == note_pubkey
    )
    assert note_signature_message(ck1, amount) == cert["message"]
    assert note_signature_digest(ck1, amount).hex() == cert["digest"]
    assert (
        verify_note_signature(ck1, domain, amount, cert["cs1"], mint["mintPubkey"])
        is Certification.CERTIFIED_OVER_Q
    )
    assert not verify_note_signature(ck1, domain, amount + 1, cert["cs1"], mint["mintPubkey"])
    # the certificate is sound, but the spend does not open the note there
    assert not verify_note_signature(
        ck1, "elsewhere." + domain, amount, cert["cs1"], mint["mintPubkey"]
    )


@pytest.mark.parametrize(
    "case", _cases(_PART2, "valid"), ids=lambda c: f"{c['type']}: {c['why']}"
)
def test_part2_accepts(case):
    decoded = _PART2_DECODERS[case["type"]](case["value"])
    if isinstance(decoded, Cx1):
        decoded = decoded.pubkey_x_only + decoded.chain_code
    assert decoded is not None and decoded.hex() == case["bytes"]
    assert _PART2_TESTS[case["type"]](case["value"]) is True


@pytest.mark.parametrize(
    "case", _cases(_PART2, "invalid"), ids=lambda c: f"{c['type']}: {c['why']}"
)
def test_part2_refuses(case):
    assert case["why"]
    assert _PART2_DECODERS[case["type"]](case["value"]) is None
    assert _PART2_TESTS[case["type"]](case["value"]) is False


# ---- a Part 2 branch rooted in a Nostr key ----
#
# nostr-seed.json is an extension, not LUD-25, and says so. heartwood-esp32
# derives the same branch on the device, so the two have to agree on every
# value from one identity key or its notes do not come back from the nsec.


def test_nostr_seed_is_marked_as_an_extension():
    spec = load_vectors("nostr-seed.json")
    assert spec["extension"] is True
    assert spec["label"] == NOSTR_CASH_SEED_LABEL


@pytest.mark.parametrize(
    "case",
    _cases("nostr-seed.json", "cases"),
    ids=lambda c: f"{c['identityPubkey'][:8]}/{c['host']}",
)
def test_nostr_seed(case):
    identity = bytes.fromhex(case["identity"])
    # the key the lightning address's npub encodes
    public = PrivateKey(identity).public_key.format(compressed=True)[1:]
    assert public.hex() == case["identityPubkey"]

    seed = derive_nostr_cash_seed(identity)
    assert seed.hex() == case["seed"]
    node = derive_nostr_address_node(identity, case["host"])
    assert cash_node_to_hex(node) == case["addressNode"]
    # nothing but the ordinary address path from that seed
    plain = derive_cash_address_node(derive_cash_root(seed), case["host"])
    assert cash_node_to_hex(plain) == case["addressNode"]

    cx1 = cash_node_to_cx1(node)
    assert encode_cx1(cx1.pubkey_x_only, cx1.chain_code) == case["cx1"]
    assert decode_cx1(case["cx1"]) == cx1
    assert spend_domain_of(case["host"]) == case["domain"]

    assert case["notes"]
    for note in case["notes"]:
        sk = derive_note_secret_key(node.private_key, node.chain_code, note["index"])
        assert sk.hex() == note["noteSecretKey"]
        pk = derive_note_pubkey(cx1.pubkey_x_only, cx1.chain_code, note["index"])
        assert pk.hex() == note["notePubkey"]
        assert encode_cp1(pk) == note["cp1"]
        _grade_key_path_note(sk, pk, note, case["domain"])


# ---- LUD-25's own published Test Vectors ----
#
# spec-vectors.json transcribes 25.md's "Test Vectors" section, so every value
# here is what the spec document itself publishes, not just this project's own
# internally generated fixtures. Checked against the library's real functions.

_SPEC = "spec-vectors.json"


def _spec_branch(case: dict):
    root = derive_cash_root(bytes.fromhex(case["seedHex"]))
    host = case["domain"]
    assert derive_cash_child(root, 0).private_key.hex() == case["cashHashingKey"]
    assert list(cash_domain_indices(root, host)) == case["domainIndices"]

    branch = derive_cash_address_node(root, host)
    assert cash_node_to_hex(branch) == cash_node_to_hex(derive_cash_domain_node(root, host))
    assert branch.private_key.hex() == case["branchPrivateKey"]
    assert branch.chain_code.hex() == case["chainCode"]

    cx1 = cash_node_to_cx1(branch)
    assert cx1.pubkey_x_only.hex() == case["branchPubkeyXOnly"]
    assert encode_cx1(cx1.pubkey_x_only, cx1.chain_code) == case["cx1"]
    return branch, cx1


@pytest.mark.parametrize("name", ["vector1", "vector2"])
def test_spec_vector_branch_and_notes(name):
    case = load_vectors(_SPEC)[name]
    branch, cx1 = _spec_branch(case)
    for note in case["notes"]:
        index = note["index"]
        pk = derive_note_pubkey(cx1.pubkey_x_only, cx1.chain_code, index)
        assert pk.hex() == note["pk"], index
        assert encode_cp1(pk) == note["cp1"], index
        sk = derive_note_secret_key(branch.private_key, branch.chain_code, index)
        assert sk.hex() == note["sk"], index
        # x(sk_i . G) == pk_i, the round trip 25.md calls out explicitly
        assert PrivateKey(sk).public_key_xonly.format() == pk, index


def test_spec_vector_address_proofs():
    case = load_vectors(_SPEC)["vector2"]
    branch, _ = _spec_branch(case)
    sk0 = derive_note_secret_key(branch.private_key, branch.chain_code, 0)
    for proof in case["addressProofs"]:
        action, domain, username = proof["action"], proof["domain"], proof["username"]
        assert domain == case["domain"]
        assert address_proof_message(action, domain, username) == proof["message"]
        assert address_proof_digest(action, domain, username).hex() == proof["digest"]
        assert sign_address_proof(sk0, action, domain, username).hex() == proof["signature"]


def test_spec_vector_ck1():
    case = load_vectors(_SPEC)["vector3"]
    sk = bytes.fromhex(case["secretKey"])
    q = bytes.fromhex(case["Q"])
    assert PrivateKey(sk).public_key_xonly.format() == q
    assert encode_cp1(q) == case["cp1"]
    domain = case["domain"]
    assert spend_prevout(domain).hex() == case["prevoutTxid"]
    assert case["spentScriptPubKey"] == "5120" + case["Q"]
    # every SigMsg field, in order, is exactly the whole SigMsg
    fields = case["sigMsgFields"]
    order = [
        "hash_type", "nVersion", "nLockTime", "sha_prevouts", "sha_amounts",
        "sha_scriptpubkeys", "sha_sequences", "sha_outputs", "spend_type", "input_index",
    ]
    assert list(fields) == order
    assert "".join(fields[name] for name in order) == case["sigMsg"]
    sig_msg = spend_sig_msg(q, domain, 0, 0xFFFFFFFF)
    assert sig_msg.hex() == case["sigMsg"]
    assert len(sig_msg) == 174
    assert key_path_sighash(q, domain).hex() == case["sighash"]
    assert case["auxRand"] == "00" * 32
    payload = sign_note_ownership(sk, domain)
    assert payload[:32] == q
    assert payload[32:].hex() == case["signature"]
    assert encode_ck1(payload) == case["ck1"]
    # the canonical spend transaction, serialised here with its witness rather
    # than by the library: version, segwit marker and flag, one input spending
    # (prevout, 0) with an empty scriptSig and a final sequence, one empty
    # zero-value output, the witness [sig], locktime 0
    tx = (
        "02000000" + "0001" + "01" + case["prevoutTxid"] + "00000000" + "00" + "ffffffff"
        + "01" + "0000000000000000" + "00" + "01" + "40" + case["signature"] + "00000000"
    )
    assert tx == case["spendTransaction"]
    assert note_id_of(case["ck1"]) == case["Q"]
    verified = verify_spend(case["ck1"], domain)
    assert verified is not None and verified.output_key == q and not verified.legacy
    # "The same ck1 submitted to a SERVICE on any other domain fails"
    assert verify_spend(case["ck1"], "cash.example.com") is None


def test_spec_vector_cs1():
    case = load_vectors(_SPEC)["vector4"]
    mint_key = PrivateKey(bytes.fromhex(case["mintPrivateKey"]))
    assert mint_key.public_key.format(compressed=True).hex() == case["mintPubkey"]
    pk, other = case["notePubkey"], case["otherNotePubkey"]
    for cert in case["certificates"]:
        amount = cert["amountMsat"]
        assert note_signature_message_for_hash(pk, amount) == cert["message"]
        digest = note_signature_digest_for_hash(pk, amount)
        assert digest.hex() == cert["digest"]
        signature = mint_key.sign_recoverable(digest, hasher=None)
        assert signature.hex() == cert["signature"]
        assert encode_cs1_with_amount(amount, signature) == cert["cs1"]
        assert (
            verify_note_signature_for_key(pk, amount, cert["signature"], case["mintPubkey"])
            is Certification.CERTIFIED_OVER_Q
        )
        assert not verify_note_signature_for_key(
            other, amount, cert["signature"], case["mintPubkey"]
        )


def test_spec_vector_bearer_note():
    case = load_vectors(_SPEC)["vector5"]
    preimage = bytes.fromhex(case["preimage"])
    h = hashlib.sha256(preimage).digest()
    assert h.hex() == case["h"]
    leaf = bearer_leaf(h)
    assert leaf.hex() == case["leaf"]
    leaf_hash = tap_leaf_hash(leaf)
    assert leaf_hash.hex() == case["tapleafHash"]
    assert NUMS_KEY.hex() == case["H"]
    # t, independently: tagged_hash("TapTweak", H || tapleaf_hash)
    tag = hashlib.sha256(b"TapTweak").digest()
    assert hashlib.sha256(tag + tag + NUMS_KEY + leaf_hash).hexdigest() == case["t"]
    note = bearer_note(h)
    assert note.output_key.hex() == case["Q"]
    assert note.control_block.hex() == case["controlBlock"]
    assert encode_cp1(note.output_key) == case["cp1"]
    assert bearer_note_id(case["h"]) == case["Q"]
    assert bearer_cw1(case["preimage"]) == case["cw1"]
    # the preimage and the full cw1 are the same spend, at any domain
    for spend in (case["preimage"], case["cw1"]):
        for domain in ("mint.example", "cash.example.com"):
            verified = verify_spend(spend, domain)
            assert verified is not None and verified.output_key == note.output_key
            assert not verified.legacy and not verified.unevaluated
        assert note_id_of(spend) == case["Q"]

    cert = case["certificate"]
    amount = cert["amountMsat"]
    assert note_signature_message_for_hash(case["Q"], amount) == cert["message"]
    assert note_signature_message(case["preimage"], amount) == cert["message"]
    assert note_signature_digest_for_hash(case["Q"], amount).hex() == cert["digest"]
    signature = bytes.fromhex(cert["signature"])
    assert encode_cs1_with_amount(amount, signature) == cert["cs1"]
    recovered = PublicKey.from_signature_and_message(
        signature, bytes.fromhex(cert["digest"]), hasher=None
    )
    assert recovered.format(compressed=True).hex() == case["mintPubkey"]
    for spend in (case["preimage"], case["cw1"]):
        assert (
            verify_note_signature(spend, "mint.example", amount, cert["cs1"], case["mintPubkey"])
            is Certification.CERTIFIED_OVER_Q
        )
    assert (
        verify_note_signature_hash(case["h"], amount, cert["cs1"], case["mintPubkey"])
        is Certification.CERTIFIED_OVER_Q
    )
    # the certified note, in short form, checked from its URL alone
    assert verify_note_url(case["certifiedNoteUrl"], case["mintPubkey"]) == (
        amount,
        Certification.CERTIFIED_OVER_Q,
    )
    assert resolve_note_input(case["certifiedNoteUrl"]) is not None


def test_an_independent_wallet_derives_the_same_literal_path():
    # Taken from lnurl-wallet itself rather than generated by the conformance
    # suite: a BIP39 phrase (no passphrase) and the branch and first note key
    # that wallet derives for one real mint host on the literal m/139'/d1..d4.
    seed = _bip39_seed(
        "dragon spell warfare girl patrol false erase surprise satisfy lucky curious ill"
    )
    assert seed.hex() == (
        "1c77403f77e0c9c558fa00cdea65ec5c5b7eb9bd10880219b9f5d8fa259aad14"
        "a81e9ad409641fd61ba3024de788cd88a1f0a27f0ff0a1a8ae140bd17bc3ee5c"
    )
    node = derive_cash_address_node(derive_cash_root(seed), "mint.lnurlcash.com")
    assert node.private_key.hex() == (
        "ec94d2f4f89e8ea4f4335970e9a7781e30b4223eb405b070f9e3930afccbdc9b"
    )
    assert node.chain_code.hex() == (
        "62ba198d1cf6f086f85f867aff7f8d6845a65dd93152df219f1815d1f707bc99"
    )
    cx1 = cash_node_to_cx1(node)
    assert derive_note_pubkey(cx1.pubkey_x_only, cx1.chain_code, 0).hex() == (
        "6fb7c0137fc17fccb337947b361580b7686219f2eeab9d47ed52a49191d5136c"
    )
