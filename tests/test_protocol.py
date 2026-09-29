"""Runs against the conformance repo's mock mint - a real HTTP server that can
be told to misbehave. The happy paths matter, but the adversarial modes are
the reason this suite exists: a library that only works against a well-behaved
SERVICE has not been tested at all."""

from __future__ import annotations

import secrets as _secrets
import time

import httpx
import pytest

from lnurlcash_kit import (
    DEFAULT_POLICY,
    AmbiguousMint,
    AmbiguousMutation,
    LnurlcashClient,
    LnurlcashError,
    NotePending,
    NoteSpent,
    NoteUnknown,
    Certification,
    OutputInUse,
    Policy,
    ProtocolError,
    RequestRefused,
    ServiceRejected,
    UnverifiableNote,
    bearer_cw1,
    bearer_note_id,
    build_note_url,
    encode_ck1,
    encode_cp1,
    hash_k1,
    new_secrets_of,
    resolve_note_input,
    sign_note_ownership,
    verify_note_signature,
)
from lnurlcash_kit.protocol import (
    mint_address_request,
    note_info_by_hash_request,
    note_info_request,
)


def secret() -> str:
    return _secrets.token_hex(32)


@pytest.fixture
def client() -> LnurlcashClient:
    return LnurlcashClient(timeout=10.0)


@pytest.fixture
def no_retry_client() -> LnurlcashClient:
    """A client that gives up on the first ambiguous answer, as every client
    did before LUD-25 required a SERVICE to replay a retried mutation.

    The tests that assert what an unresolved mutation carries need it: with
    retries on, a conforming mint simply answers again and there is nothing
    left to carry.
    """
    return LnurlcashClient(timeout=10.0, mutation_retries=0)


# ---- the informational GET ----


def test_reports_value_and_never_burns(mint, client):
    m = mint()
    k1 = secret()
    m.credit(k1, 21000)

    info = client.fetch_note_info(m.note_url(k1))
    assert info.max_withdrawable == 21000
    assert info.k1 == k1
    assert m.note_state(k1) == "outstanding"

    assert client.fetch_note_info(m.note_url(k1)).max_withdrawable == 21000


def test_max_withdrawable_beats_the_urls_own_claim(mint, client):
    m = mint()
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1, 2_100_000))
    assert info.max_withdrawable == 21000


def test_refuses_a_service_that_echoes_a_different_k1(mint, client):
    m = mint(echoWrongK1=True)
    k1 = secret()
    m.credit(k1, 21000)
    with pytest.raises(ProtocolError):
        client.fetch_note_info(m.note_url(k1))


def test_unknown_and_spent_are_different_answers(mint, client):
    m = mint()
    known = secret()
    m.credit(known, 21000)
    with pytest.raises(NoteUnknown):
        client.fetch_note_info(m.note_url(secret()))

    info = client.fetch_note_info(m.note_url(known))
    client.rotate_note(info.callback, known)
    with pytest.raises(NoteSpent):
        client.fetch_note_info(m.note_url(known))


# The mintPubkey check. Parsed straight from a body: the mock mint always
# publishes a key, and what needs grading is which policy refuses a mint that
# does not, and which admits it.

_NOTE_K1 = "aa" * 32
_MINT_PUBKEY = "03" + "4f" * 32


def _withdraw_request(**extra):
    return {
        "tag": "withdrawRequest",
        "callback": "https://mint.example/w/cb",
        "k1": _NOTE_K1,
        "maxWithdrawable": 21000,
        **extra,
    }


def _parse_note_info(body, policy=None):
    url = f"https://mint.example/w?k1={_NOTE_K1}"
    if policy is None:
        return note_info_request(url).parse(body)
    return note_info_request(url, policy).parse(body)


def _parse_note_info_by_hash(body, policy=None):
    h = hash_k1(_NOTE_K1)
    if policy is None:
        return note_info_by_hash_request("https://mint.example/w", h).parse(body)
    return note_info_by_hash_request("https://mint.example/w", h, policy).parse(body)


@pytest.mark.parametrize("parse", [_parse_note_info, _parse_note_info_by_hash])
def test_a_mint_publishing_no_valid_mint_pubkey_is_refused_by_default(parse):
    assert parse(_withdraw_request(mintPubkey=_MINT_PUBKEY)).mint_pubkey == _MINT_PUBKEY
    for body in (_withdraw_request(), _withdraw_request(mintPubkey="4f" * 32)):
        with pytest.raises(ProtocolError, match="mintPubkey"):
            parse(body)
        # require_signatures no longer carries this check: turning it off,
        # which is now the default anyway, admits nothing extra
        with pytest.raises(ProtocolError, match="mintPubkey"):
            parse(body, Policy(require_signatures=False))


@pytest.mark.parametrize("parse", [_parse_note_info, _parse_note_info_by_hash])
def test_a_part1_only_mint_is_admitted_with_require_mint_pubkey_off(parse):
    info = parse(_withdraw_request(), Policy(require_mint_pubkey=False))
    assert info.mint_pubkey is None
    assert info.max_withdrawable == 21000
    # and it is its own switch: demanding the Part 1 signature does not put
    # the key back
    both = Policy(require_signatures=True, require_mint_pubkey=False)
    assert parse(_withdraw_request(), both).mint_pubkey is None


def test_the_client_applies_require_mint_pubkey():
    def answer(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_withdraw_request())

    url = f"https://mint.example/w?k1={_NOTE_K1}"
    with httpx.Client(transport=httpx.MockTransport(answer)) as http:
        with pytest.raises(ProtocolError, match="mintPubkey"):
            LnurlcashClient(client=http).fetch_note_info(url)
        lenient = LnurlcashClient(client=http, policy=Policy(require_mint_pubkey=False))
        assert lenient.fetch_note_info(url).mint_pubkey is None


def test_the_default_policy_is_the_part2_one():
    # a cs1 on every cp1 output is not a field: nothing turns it off
    assert DEFAULT_POLICY == Policy()
    assert DEFAULT_POLICY.require_signatures is False
    assert DEFAULT_POLICY.require_mint_pubkey is True
    assert LnurlcashClient().policy == DEFAULT_POLICY


# ---- rotate ----


def test_rotate_burns_the_old_secret_and_mints_one_the_service_never_saw(mint, client):
    m = mint()
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))

    rotated = client.rotate_note(info.callback, k1)
    assert rotated.k1 != k1
    assert m.note_state(k1) == "burned"
    assert m.note_state(rotated.k1) == "outstanding"
    assert client.fetch_note_info(m.note_url(rotated.k1)).max_withdrawable == 21000


def test_rotate_signature_verifies_offline(mint, client):
    # the mint certifies the bearer note it minted over hex(Q), and the
    # default neither demands the certificate nor drops it
    m = mint()
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))
    rotated = client.rotate_note(info.callback, k1)

    assert rotated.signature
    assert (
        verify_note_signature(rotated.k1, m.url, 21000, rotated.signature, m.pubkey)
        is Certification.CERTIFIED_OVER_Q
    )
    assert not verify_note_signature(rotated.k1, m.url, 21001, rotated.signature, m.pubkey)


def test_accepts_the_other_recovery_id_layout(mint, client):
    m = mint(signatureLayout="leading")
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))
    rotated = client.rotate_note(info.callback, k1)
    assert (
        verify_note_signature(rotated.k1, m.url, 21000, rotated.signature, m.pubkey)
        is Certification.CERTIFIED_OVER_Q
    )


def test_a_no_signer_legacy_mint_is_tolerated_by_default(mint, client):
    """The tolerant default preserves a landed legacy output when the
    reference mint has no signer; strict reference-wallet parity is separate."""
    m = mint(signatures=False)
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))
    rotated = client.rotate_note(info.callback, k1)
    assert rotated.signature is None
    assert m.note_state(k1) == "burned"
    assert m.note_state(rotated.k1) == "outstanding"


def test_no_signer_split_and_merge_outputs_are_tolerated(mint, client):
    m = mint(signatures=False)
    k1 = secret()
    m.credit(k1, 21000)
    split = client.split_note(f"{m.url}/w/cb", [k1], 5000)
    assert split.signature is None and split.change_signature is None
    assert m.note_state(split.k1) == "outstanding"
    assert m.note_state(split.change) == "outstanding"

    merged = client.merge_notes(f"{m.url}/w/cb", [split.k1, split.change])
    assert merged.signature is None
    assert client.fetch_note_info(m.note_url(merged.k1)).max_withdrawable == 21000


def test_require_signatures_still_refuses_an_unsigned_plain_note(mint):
    """A caller matching the committed reference wallet can demand the raw
    Part 1 signature over the hash.

    The refusal has to be the loud kind - but the rotate LANDED, and the fresh
    secret is the only key to the note it minted, so the exception carries it
    out. Raising without it would be the library destroying real money to make
    a point about a signature.
    """
    m = mint(signatures=False)
    client = LnurlcashClient(timeout=10.0, policy=Policy(require_signatures=True))
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))
    with pytest.raises(UnverifiableNote) as raised:
        client.rotate_note(info.callback, k1)
    kept = new_secrets_of(raised.value)
    assert len(kept) == 1
    # the note the caller was refused is real, outstanding, and reachable with
    # nothing but the secret the exception handed back
    assert m.note_state(kept[0]) == "outstanding"

    # and a split hands back both, in output order, since both landed
    with pytest.raises(UnverifiableNote) as raised:
        client.split_note(info.callback, kept, 5000)
    split_off, change = new_secrets_of(raised.value)
    assert client.fetch_note_info(m.note_url(split_off)).max_withdrawable == 5000
    assert client.fetch_note_info(m.note_url(change)).max_withdrawable == 16000


def test_ignores_a_secret_the_service_tries_to_hand_back(mint, client):
    m = mint(serverGeneratedSecrets=True)
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))
    rotated = client.rotate_note(info.callback, k1)
    # taking the mint's offered secret would hand it a permanent copy of the
    # note it just issued
    assert rotated.k1 != "a" * 64
    assert m.note_state(rotated.k1) == "outstanding"


# ---- split and merge ----


def test_split_produces_an_amount_and_its_change(mint, client):
    m = mint()
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))

    result = client.split_note(info.callback, [k1], 5000)
    assert m.note_state(k1) == "burned"
    assert client.fetch_note_info(m.note_url(result.k1)).max_withdrawable == 5000
    assert client.fetch_note_info(m.note_url(result.change)).max_withdrawable == 16000
    assert verify_note_signature(result.k1, m.url, 5000, result.signature, m.pubkey)
    assert verify_note_signature(
        result.change, m.url, 16000, result.change_signature, m.pubkey
    )


def test_split_takes_several_notes_at_once(mint, client):
    m = mint()
    a, b = secret(), secret()
    m.credit(a, 21000)
    m.credit(b, 9000)
    info = client.fetch_note_info(m.note_url(a))

    result = client.split_note(info.callback, [a, b], 25000)
    assert m.note_state(a) == "burned"
    assert m.note_state(b) == "burned"
    assert client.fetch_note_info(m.note_url(result.k1)).max_withdrawable == 25000
    assert client.fetch_note_info(m.note_url(result.change)).max_withdrawable == 5000


def test_merge_sums(mint, client):
    m = mint()
    parts = [secret() for _ in range(3)]
    for i, k1 in enumerate(parts):
        m.credit(k1, 1000 * (i + 1))
    info = client.fetch_note_info(m.note_url(parts[0]))

    merged = client.merge_notes(info.callback, parts)
    for part in parts:
        assert m.note_state(part) == "burned"
    assert client.fetch_note_info(m.note_url(merged.k1)).max_withdrawable == 6000


def test_refuses_a_mutation_naming_no_note(mint, client):
    m = mint()
    with pytest.raises(RequestRefused):
        client.merge_notes(f"{m.url}/w/cb", [])
    with pytest.raises(RequestRefused):
        client.split_note(f"{m.url}/w/cb", [], 1000)


def test_settle_resolves_what_an_output_is_really_worth(mint, client):
    m = mint()
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))
    result = client.split_note(info.callback, [k1], 5000)

    # the caller does not know the change is 16000 - only the service does
    settled_k1, amount, _sig, _cb = client.settle_note(
        m.note_url(k1), result.change, 0, result.change_signature
    )
    assert amount == 16000
    # and it was rotated on the way, so the GET-exposed secret is gone
    assert settled_k1 != result.change
    assert m.note_state(result.change) == "burned"


# ---- melt ----


def test_melt_ok_means_in_flight_not_spent(mint, client):
    m = mint(meltNeverSettles=True)
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))

    result = client.melt_note(info.callback, k1, "lnbc210n1pjqrstuvwxyz")
    assert result.pr == "lnbc210n1pjqrstuvwxyz"
    assert m.note_state(k1) == "pending"


def test_pending_locks_out_other_operations(mint, client):
    m = mint(meltNeverSettles=True)
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))
    client.melt_note(info.callback, k1, "lnbc210n1pjqrstuvwxyz")

    with pytest.raises(NotePending):
        client.rotate_note(info.callback, k1)
    with pytest.raises(NotePending):
        client.melt_note(info.callback, k1, "lnbc210n1pjqrstuvwxyz")


def test_a_failed_melt_restores_the_note(mint, client):
    m = mint(meltAlwaysFails=True)
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))
    client.melt_note(info.callback, k1, "lnbc210n1pjqrstuvwxyz")

    time.sleep(0.15)
    # a failed melt is never reported through the callback - it is only
    # observable as the note becoming spendable again
    assert m.note_state(k1) == "outstanding"
    assert client.fetch_note_info(m.note_url(k1)).max_withdrawable == 21000


def test_a_settled_melt_burns_the_note_and_proves_it(mint, client):
    m = mint()
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))
    result = client.melt_note(info.callback, k1, "lnbc210n1pjqrstuvwxyz")

    time.sleep(0.15)
    assert m.note_state(k1) == "burned"

    proof = client.fetch_invoice_verification(result.verify)
    assert proof.settled is True
    # the melt's preimage is not the note secret: the note that funded this
    # payment was already burned by the time the proof existed
    assert proof.preimage != k1


# ---- minting ----


def test_mints_a_note_the_service_never_saw_the_secret_of(mint, client):
    m = mint()
    pay = client.fetch_pay_request(f"{m.url}/.well-known/lnurlp/mint")
    assert pay.withdraw_link
    # LUD-25 minting is comment-bound, so a mint MUST leave room for the
    # 64-character commitment. Without it there is nowhere to name the note.
    assert pay.names_mint_output()
    assert pay.comment_allowed == 64

    # The wallet chooses the secret, before any invoice exists, and persists
    # it before paying. The SERVICE is told sha256 of it and nothing more.
    mint_secret = secret()
    invoice = client.request_mint_invoice(pay.callback, 21000, mint_secret)
    assert invoice.disposable is False
    assert invoice.verify

    payment_hash = invoice.verify.rsplit("/", 1)[-1]
    m.settle(payment_hash)

    verified = client.fetch_invoice_verification(invoice.verify)
    assert verified.settled is True
    # The preimage is settlement proof and nothing else. Every node that
    # forwarded the payment learned it; under the earlier draft that made all
    # of them holders of the note. Here it redeems nothing.
    preimage = verified.preimage
    assert hash_k1(preimage) == payment_hash
    assert preimage != mint_secret
    with pytest.raises((NoteUnknown, NoteSpent, ServiceRejected)):
        client.fetch_note_info(build_note_url(pay.withdraw_link, preimage))

    # The wallet's own secret is the note.
    info = client.fetch_note_info(build_note_url(pay.withdraw_link, mint_secret))
    assert info.max_withdrawable == 21000
    rotated = client.rotate_note(info.callback, mint_secret)
    assert m.note_state(mint_secret) == "burned"
    assert m.note_state(rotated.k1) == "outstanding"


def test_refuses_to_pay_for_a_note_it_cannot_name(mint, client):
    m = mint()
    pay = client.fetch_pay_request(f"{m.url}/.well-known/lnurlp/mint")

    # A malformed commitment is refused before the request leaves, so a WALLET
    # never pays for a quote the SERVICE was always going to reject.
    with pytest.raises(RequestRefused):
        client.request_mint_invoice(pay.callback, 21000, "not-a-32-byte-secret")

    # And an unnamed mint quote is refused by the SERVICE itself, before any
    # invoice exists to pay.
    with pytest.raises(ServiceRejected):
        client.request_invoice(pay.callback, 21000)


def test_reads_an_advertised_fee(mint, client):
    m = mint(baseFeeMsat=1000, feePpm=2000)
    pay = client.fetch_pay_request(f"{m.url}/.well-known/lnurlp/mint")
    assert pay.mint_fee.base_fee_msat == 1000
    assert pay.mint_fee.fee_ppm == 2000


def test_no_fee_advertised_means_fee_free(mint, client):
    m = mint()
    pay = client.fetch_pay_request(f"{m.url}/.well-known/lnurlp/mint")
    assert pay.mint_fee is None


def test_a_fee_charging_mint_credits_the_net_amount(mint, client):
    m = mint(baseFeeMsat=1000, feePpm=2000)
    pay = client.fetch_pay_request(f"{m.url}/.well-known/lnurlp/mint")
    mint_secret = secret()
    invoice = client.request_mint_invoice(pay.callback, 100000, mint_secret)
    payment_hash = invoice.verify.rsplit("/", 1)[-1]
    m.settle(payment_hash)

    info = client.fetch_note_info(build_note_url(pay.withdraw_link, mint_secret))
    # 100000 - 1000 flat - 200 proportional
    from lnurlcash_kit import apply_mint_fee

    assert info.max_withdrawable == apply_mint_fee(100000, pay.mint_fee) == 98800


def test_finds_the_experimental_mint_address(mint, client):
    m = mint()
    address = client.fetch_mint_address(f"{m.url}/.well-known/lnurlw/mint")
    assert address.node_pubkey == m.pubkey
    assert address.pay_link.endswith("/.well-known/lnurlp/mint")


def test_reads_the_node_stats_a_mint_address_advertises(mint, client):
    m = mint()
    address = client.fetch_mint_address(f"{m.url}/.well-known/lnurlw/mint")
    # the wire field is nodeCapacity - renamed here, so it only arrives if it
    # is mapped rather than passed through under its own name
    assert address.node_capacity_msat == 500_000_000
    assert address.node_num_channels == 4
    assert address.node_num_peers == 6


def test_a_sunsetting_mint_refuses_definitively(mint, client):
    m = mint(sunset=True)
    pay = client.fetch_pay_request(f"{m.url}/.well-known/lnurlp/mint")
    with pytest.raises(ServiceRejected):
        client.request_invoice(pay.callback, 21000)


# ---- ambiguous outcomes ----


def test_a_lost_rotate_completes_by_asking_again(mint, client):
    """The mutation landed and the answer was lost on the way back. LUD-25 now
    requires the SERVICE to answer the identical request with the success it
    already gave, so asking a second time turns this from an unresolved maybe
    into a completed rotate - the caller never sees an exception at all."""
    m = mint(dropAfterMutation=True)
    k1 = secret()
    m.credit(k1, 21000)

    rotated = client.rotate_note(f"{m.url}/w/cb", k1)
    assert m.note_state(k1) == "burned"
    assert m.note_state(rotated.k1) == "outstanding"
    # the replay repeats the signature, so a note recovered this way is as
    # verifiable as one whose first answer arrived
    assert rotated.signature is not None


def test_a_mint_that_will_not_replay_still_hands_the_secrets_back(mint, client):
    """A SERVICE that has not implemented the replay rule answers the second
    attempt as an already-spent input, exactly as before. The library cannot
    tell that from a genuine double spend - at the wire they are the same
    answer - so it hands the secrets back rather than a verdict."""
    m = mint(dropAfterMutation=True, retriedMutation="refuse")
    k1 = secret()
    m.credit(k1, 21000)

    with pytest.raises(LnurlcashError) as raised:
        client.rotate_note(f"{m.url}/w/cb", k1)
    rescued = new_secrets_of(raised.value)
    assert len(rescued) == 1
    assert m.note_state(rescued[0]) == "outstanding"


def test_a_lost_rotate_preserves_its_fresh_secret(mint, no_retry_client):
    client = no_retry_client
    m = mint(dropAfterMutation=True)
    k1 = secret()
    m.credit(k1, 21000)

    with pytest.raises(AmbiguousMutation) as caught:
        client.rotate_note(f"{m.url}/w/cb", k1)
    assert len(caught.value.new_secrets) == 1

    # the mutation did land: the input is burned and the output exists, keyed
    # by the hash of a secret only the caller holds
    assert m.note_state(k1) == "burned"
    rescued = caught.value.new_secrets[0]
    assert m.note_state(rescued) == "outstanding"
    assert client.fetch_note_info(m.note_url(rescued)).max_withdrawable == 21000


def test_a_lost_split_preserves_both_secrets_in_output_order(mint, no_retry_client):
    client = no_retry_client
    m = mint(dropAfterMutation=True)
    k1 = secret()
    m.credit(k1, 21000)

    with pytest.raises(AmbiguousMutation) as caught:
        client.split_note(f"{m.url}/w/cb", [k1], 5000)
    split_off, change = caught.value.new_secrets
    assert client.fetch_note_info(m.note_url(split_off)).max_withdrawable == 5000
    assert client.fetch_note_info(m.note_url(change)).max_withdrawable == 16000


def test_probing_resolves_the_ambiguity(mint, no_retry_client):
    client = no_retry_client
    m = mint(dropAfterMutation=True)
    k1 = secret()
    m.credit(k1, 21000)
    with pytest.raises(AmbiguousMutation):
        client.rotate_note(f"{m.url}/w/cb", k1)
    # gone: the burn landed, so the rescued secret is the only money left
    assert client.probe_burned_note(m.note_url(k1)) == "gone"

    live = mint()
    alive = secret()
    live.credit(alive, 21000)
    assert client.probe_burned_note(live.note_url(alive)) == "live"

    offline = LnurlcashClient(offline=True)
    assert offline.probe_burned_note(live.note_url(alive)) == "unknown"


def test_a_200_that_confirms_nothing_is_ambiguous(mint, no_retry_client):
    client = no_retry_client
    m = mint(unconfirmedMutation=True)
    k1 = secret()
    m.credit(k1, 21000)
    with pytest.raises(AmbiguousMutation):
        client.rotate_note(f"{m.url}/w/cb", k1)
    assert m.note_state(k1) == "burned"


def test_an_unreadable_response_is_ambiguous(mint, client):
    m = mint(malformedJson=True)
    k1 = secret()
    m.credit(k1, 21000)
    with pytest.raises(AmbiguousMutation):
        client.rotate_note(f"{m.url}/w/cb", k1)


def test_a_timeout_is_ambiguous_not_failure(mint):
    m = mint(slowMs=500)
    k1 = secret()
    m.credit(k1, 21000)
    impatient = LnurlcashClient(timeout=0.05)
    with pytest.raises(AmbiguousMutation):
        impatient.rotate_note(f"{m.url}/w/cb", k1)


def test_a_refused_request_is_definitely_not_sent(mint):
    m = mint()
    k1 = secret()
    m.credit(k1, 21000)
    offline = LnurlcashClient(offline=True)
    with pytest.raises(RequestRefused) as caught:
        offline.rotate_note(f"{m.url}/w/cb", k1)
    assert not isinstance(caught.value, AmbiguousMint)
    assert m.note_state(k1) == "outstanding"


def test_refuses_a_callback_url_it_would_not_fetch(mint, client):
    m = mint()
    k1 = secret()
    m.credit(k1, 21000)
    with pytest.raises(RequestRefused):
        client.rotate_note("http://evil.example/cb", k1)


# ---- a service that lies ----


def test_a_lying_service_cannot_inflate_past_what_it_signed(mint, client):
    m = mint(lieAboutValue=1_000_000)
    k1 = secret()
    signature = m.credit(k1, 21000)

    info = client.fetch_note_info(m.note_url(k1))
    assert info.max_withdrawable == 1_021_000
    # the signature was issued over the true amount, so the inflated one does
    # not verify - an offline holder catches this without asking anyone
    assert not verify_note_signature(k1, m.url, info.max_withdrawable, signature, m.pubkey)
    assert verify_note_signature(k1, m.url, 21000, signature, m.pubkey)
    # and the certificate the lookup hands out says the same
    assert not verify_note_signature(
        k1, m.url, info.max_withdrawable, info.signature, m.pubkey
    )


def test_settle_surfaces_a_rotate_that_may_have_applied(mint):
    """A rotate whose answer is lost must not come back as a settled note.

    If the request landed, the SERVICE burned that k1 and minted the rotated
    note under h, and the fresh secret carried on the error is the only copy
    of it anywhere. This used to catch bare ``Exception`` and return the
    burned k1, so the caller kept a dead secret and the live one was dropped.
    """
    m = mint(dropAfterMutation=True)
    # Retrying off, so the ambiguity survives to the caller. With the default
    # the SERVICE replays the original success per LUD-25's "Retrying a
    # mutation" and this resolves cleanly, which is what that rule is for.
    client = LnurlcashClient(mutation_retries=0)
    k1 = secret()
    m.credit(k1, 21000)

    with pytest.raises(AmbiguousMint) as caught:
        client.settle_note(m.note_url(k1), k1, 0)

    fresh = new_secrets_of(caught.value)
    assert len(fresh) == 1, "the fresh secret did not survive the error"
    assert fresh[0] != k1, "the secret carried out is the one that was burned"


# The three fields the reference mint publishes on its discovery document.
# Parsed straight from a body rather than through the mock mint: the mock does
# not emit them, and what needs grading here is the mapping and what it
# refuses, not another round trip.


def _mint_address(**extra):
    body = {
        "tag": "withdrawRequest",
        "callback": "https://mint.example/w/cb",
        "payLink": "https://mint.example/.well-known/lnurlp/mint",
        "minWithdrawable": 1000,
        "maxWithdrawable": 100_000_000,
        **extra,
    }
    return mint_address_request("https://mint.example/.well-known/lnurlw/mint").parse(body)


def test_reads_every_address_the_node_announces():
    clearnet = "02aa@2.29.14.244:9735"
    onion = "02aa@abcdefghijklmnop.onion:9735"
    address = _mint_address(nodeUri=clearnet, nodeUris=[clearnet, onion])
    assert address.node_uris == (clearnet, onion)
    # the singular field is unchanged and still the first address
    assert address.node_uri == clearnet


def test_an_announced_nothing_is_none_not_empty():
    # A caller testing `is not None` and one testing len() have to reach the
    # same conclusion about a mint that announced nothing.
    assert _mint_address().node_uris is None
    assert _mint_address(nodeUris=[]).node_uris is None
    assert _mint_address(nodeUris="not a list").node_uris is None
    assert _mint_address(nodeUris=[1, "a", "", None]).node_uris == ("a",)


def test_a_closing_date_is_a_calendar_day_or_nothing():
    assert _mint_address(sunsetDate="2026-12-31").sunset_date == "2026-12-31"
    assert _mint_address(sunsetDate="2028-02-29").sunset_date == "2028-02-29"
    assert _mint_address().sunset_date is None
    # A wallet showing a holder a closing date off an unchecked string is
    # worse than showing nothing, so anything that is not a real day goes.
    for bad in (
        "31/12/2026",
        "2026-12-31T09:00:00Z",
        "20261231",
        "2026-02-31",
        "2026-02-29",
        "2026-13-01",
        20261231,
        None,
    ):
        assert _mint_address(sunsetDate=bad).sunset_date is None


def test_what_a_mint_says_it_owes_keeps_zero_distinct_from_silence():
    assert _mint_address(outstandingNotesMsat=48_000).outstanding_notes_msat == 48_000
    # "owes nothing" and "will not say" are different things to know about a
    # custodian
    assert _mint_address(outstandingNotesMsat=0).outstanding_notes_msat == 0
    assert _mint_address().outstanding_notes_msat is None
    assert _mint_address(outstandingNotesMsat="48000").outstanding_notes_msat is None


# ---- notes keyed by Q, at the mock mint ----
#
# The mock mint keys every note by hex(Q), verifies every spend in full (a ck1
# against the hostname it was reached at, 127.0.0.1 here), and certifies every
# note with a cs1 over hex(Q).


def _lookup(m, name: str):
    """The informational GET by a note's public name, through the no-I/O
    request and its parser, as a caller with its own HTTP stack makes it."""
    request = note_info_by_hash_request(f"{m.url}/w", name)
    return request.parse(httpx.get(request.url).json())


def _test_key(label: str, m) -> tuple[bytes, str, str]:
    """A note key made for these tests alone, with its cp1 and the ck1 that
    spends it at ``m``."""
    import hashlib

    key = hashlib.sha256(f"lnurlcash-py test key {label}".encode()).digest()
    payload = sign_note_ownership(key, m.url)
    return key, encode_cp1(payload[:32]), encode_ck1(payload)


def test_a_key_path_note_round_trips_at_the_mint(mint, client):
    m = mint()
    _, cp1, ck1 = _test_key("a", m)
    m.credit(ck1, 21000)

    # the lookup verifies the spend, echoes it, and hands out the certificate
    info = client.fetch_note_info(m.note_url(ck1))
    assert info.k1 == ck1 and info.max_withdrawable == 21000
    assert (
        verify_note_signature(ck1, m.url, 21000, info.signature, m.pubkey)
        is Certification.CERTIFIED_OVER_Q
    )
    # looked up by its cp1, the spend never leaves this process
    by_key = _lookup(m, cp1)
    assert by_key.max_withdrawable == 21000 and by_key.signature == info.signature

    # rotate into another key; the output comes back certified
    _, cp1_b, ck1_b = _test_key("b", m)
    result = client.rotate_note_with_hash(info.callback, ck1, cp1_b)
    assert m.note_state(ck1) == "burned"
    assert (
        verify_note_signature(ck1_b, m.url, 21000, result.signature, m.pubkey)
        is Certification.CERTIFIED_OVER_Q
    )

    # and back out to a bearer note this client draws
    rotated = client.rotate_note(info.callback, ck1_b)
    assert (
        verify_note_signature(rotated.k1, m.url, 21000, rotated.signature, m.pubkey)
        is Certification.CERTIFIED_OVER_Q
    )


def test_a_ck1_for_another_mint_opens_nothing(mint, client):
    m = mint()
    key, _, ck1 = _test_key("c", m)
    m.credit(ck1, 21000)
    foreign = encode_ck1(sign_note_ownership(key, "elsewhere.example"))

    with pytest.raises(NoteUnknown):
        client.fetch_note_info(m.note_url(foreign))
    with pytest.raises(ServiceRejected):
        client.rotate_note(f"{m.url}/w/cb", foreign)
    assert m.note_state(ck1) == "outstanding"
    # and this library would not have let it through the door either
    assert resolve_note_input(m.note_url(foreign)) is None


def test_a_bearer_note_spends_by_its_full_cw1(mint, client):
    m = mint()
    preimage = secret()
    m.credit(preimage, 21000)
    cw1 = bearer_cw1(preimage)
    info = client.fetch_note_info(m.note_url(cw1))
    assert info.max_withdrawable == 21000
    # the certificate names the note, not the spelling of its spend
    for spend in (preimage, cw1):
        assert (
            verify_note_signature(spend, m.url, 21000, info.signature, m.pubkey)
            is Certification.CERTIFIED_OVER_Q
        )
    # looked up by its h, the short form of its cp1
    assert _lookup(m, hash_k1(preimage)).max_withdrawable == 21000
    rotated = client.rotate_note(info.callback, cw1)
    assert m.note_state(preimage) == "burned"
    assert m.note_state(rotated.k1) == "outstanding"


def test_an_output_already_in_use_is_refused_and_burns_nothing(mint, client):
    m = mint()
    source, taken = secret(), secret()
    m.credit(source, 21000)
    m.credit(taken, 1000)
    callback = f"{m.url}/w/cb"

    with pytest.raises(OutputInUse) as raised:
        client.rotate_note_with_hash(callback, source, hash_k1(taken))
    assert not isinstance(raised.value, (NoteSpent, NoteUnknown))
    assert new_secrets_of(raised.value) == []
    assert m.note_state(source) == "outstanding"
    # the same output named by its cp1 is the same note, and just as taken
    taken_cp1 = encode_cp1(bytes.fromhex(bearer_note_id(hash_k1(taken))))
    with pytest.raises(OutputInUse):
        client.rotate_note_with_hash(callback, source, taken_cp1)


def test_lnurl_mints_wording_of_already_in_use():
    # lnurl-mint says "Output already in use." rather than the spec's exact
    # "already in use"; a wallet retrying at its next index must see both
    def answer(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"status": "ERROR", "reason": "Output already in use."}
        )

    with httpx.Client(transport=httpx.MockTransport(answer)) as http:
        with pytest.raises(OutputInUse):
            LnurlcashClient(client=http).rotate_note_with_hash(
                "https://mint.example/w/cb", secret(), hash_k1(secret())
            )


@pytest.mark.parametrize("names", ["c", "sig", "both"])
def test_certificates_are_read_under_either_name(mint, client, names):
    # a mint that has not yet renamed sig to c (LUD-25, luds 50d740a) still
    # hands a holder its certificate
    m = mint(certificateNames=names)
    k1 = secret()
    signature = m.credit(k1, 21000)
    assert signature
    info = client.fetch_note_info(m.note_url(k1))
    assert info.signature == signature
    assert verify_note_signature(k1, m.url, 21000, info.signature, m.pubkey)
