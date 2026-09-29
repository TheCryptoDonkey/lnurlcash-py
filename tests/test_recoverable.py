"""Key-path notes and spends on the wire, and the edges of their primitives
that the conformance vectors do not reach.

The wire half builds each request and reads its URL, which is exactly what
the clients send: they GET ``Request.url`` and nothing else. The note values
are the conformance vectors', whose first branch is at mint.example, so every
key, ck1 and cs1 here is one another implementation agrees on.
"""

from __future__ import annotations

from hashlib import sha256
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from coincurve import PrivateKey

from conftest import load_vectors
from lnurlcash_kit import (
    Certification,
    Cs1,
    LnurlcashClient,
    Policy,
    ProtocolError,
    RequestRefused,
    UnverifiableNote,
    bearer_cw1,
    bearer_note_id,
    build_note_info_url_by_hash,
    cash_node_from_hex,
    decode_any_cs1,
    decode_ck1,
    decode_cp1,
    decode_cs1,
    decode_cs1_with_amount,
    decode_cx1,
    derive_cash_child,
    derive_cash_master,
    derive_cash_root,
    derive_note_pubkey,
    derive_note_secret_key,
    derive_nostr_cash_seed,
    encode_ck1,
    encode_cp1,
    encode_cs1_with_amount,
    encode_cx1,
    hash_k1,
    is_ck1,
    is_cp1,
    is_cs1_with_amount,
    is_cw1,
    is_cx1,
    new_secrets_of,
    note_id_of,
    note_lookup_of,
    note_signature_message,
    recover_note_ownership_pubkey,
    resolve_note_input,
    sign_note_ownership,
    verify_note_signature,
    verify_spend,
)
from lnurlcash_kit import bech32, recoverable
from lnurlcash_kit.protocol import (
    melt_request,
    merge_request_with_hash,
    mint_invoice_request_with_hash,
    note_info_by_hash_request,
    note_info_request,
    rotate_request_with_hash,
    split_request_with_hash,
)

K1 = "11" * 32
DOMAIN = "mint.example"
CB = "https://mint.example/w/cb"
PAY_CB = "https://mint.example/p/cb"
_CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


@pytest.fixture(scope="module")
def part2() -> dict:
    return load_vectors("part2.json")


@pytest.fixture(scope="module")
def notes(part2) -> list[dict]:
    """The first branch's notes: a, b and c below."""
    return part2["branches"][0]["notes"]


@pytest.fixture(scope="module")
def cert(part2) -> dict:
    """A certificate for the first branch's first note, at 1000 msat."""
    found = part2["certificates"][0]
    assert found["notePubkey"] == part2["branches"][0]["notes"][0]["notePubkey"]
    return found


def query(url: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(url).query)


def legacy_ck1(secret_key_hex: str) -> str:
    """The pre-Schnorr 65-byte ``r || s || recovery id`` ck1 for a note key:
    a recoverable ECDSA signature over the Lightning-signed ``LNURLcash``.

    Nothing signs one of these anymore, but notes minted before the Schnorr
    format carry one, and they stay readable so they can be rotated.
    """
    digest = sha256(sha256(b"Lightning Signed Message:LNURLcash").digest()).digest()
    signature = PrivateKey(bytes.fromhex(secret_key_hex)).sign_recoverable(digest, hasher=None)
    return bech32.encode("ck", signature, constant=bech32.BECH32M)


def digest_message_ck1(secret_key: bytes) -> bytes:
    """A 96-byte ck1 payload signed over ``sha256("LNURLcash")``, the form
    current until spends moved onto the sighash, with all-zero auxiliary
    input."""
    signer = PrivateKey(secret_key)
    digest = sha256(b"LNURLcash").digest()
    return signer.public_key_xonly.format() + signer.sign_schnorr(digest, bytes(32))


def raw_message_ck1(secret_key: bytes) -> bytes:
    """A 96-byte ck1 payload signed over the raw 9-byte ``LNURLcash`` rather
    than its sha256 digest: the scheme before 2026-09-16. coincurve's signer
    only takes 32-byte messages, so this is BIP-340 signing by hand."""
    n = _CURVE_N
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    G = (
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    )

    def add(a, b):
        if a is None:
            return b
        if b is None:
            return a
        if a[0] == b[0] and a[1] != b[1]:
            return None
        if a == b:
            lam = 3 * a[0] * a[0] * pow(2 * a[1], p - 2, p) % p
        else:
            lam = (b[1] - a[1]) * pow(b[0] - a[0], p - 2, p) % p
        x = (lam * lam - a[0] - b[0]) % p
        return x, (lam * (a[0] - x) - a[1]) % p

    def mul(point, k):
        out = None
        while k:
            if k & 1:
                out = add(out, point)
            point = add(point, point)
            k >>= 1
        return out

    def tagged(tag: bytes, data: bytes) -> bytes:
        return sha256(sha256(tag).digest() + sha256(tag).digest() + data).digest()

    message = b"LNURLcash"
    d0 = int.from_bytes(secret_key, "big")
    P = mul(G, d0)
    d = d0 if P[1] % 2 == 0 else n - d0
    px = P[0].to_bytes(32, "big")
    t = bytes(a ^ b for a, b in zip(d.to_bytes(32, "big"), tagged(b"BIP0340/aux", bytes(32))))
    k0 = int.from_bytes(tagged(b"BIP0340/nonce", t + px + message), "big") % n
    R = mul(G, k0)
    k = k0 if R[1] % 2 == 0 else n - k0
    rx = R[0].to_bytes(32, "big")
    e = int.from_bytes(tagged(b"BIP0340/challenge", rx + px + message), "big") % n
    return px + rx + ((k + e * d) % n).to_bytes(32, "big")


# ---- a note's id, any kind ----


def test_a_bearer_note_is_filed_under_its_q_and_looked_up_by_its_h():
    # a preimage and its cw1 are one spend of one note, filed by hex(Q)
    q = bearer_note_id(hash_k1(K1))
    cw1 = bearer_cw1(K1)
    for spend in (K1, K1.upper(), cw1):
        assert note_id_of(spend) == q
    # looked up by its short form, which every mint reads, or by its cp1
    assert note_lookup_of(K1) == hash_k1(K1)
    assert note_lookup_of(cw1) == encode_cp1(bytes.fromhex(q))


def test_a_key_path_note_is_filed_under_its_key_and_looked_up_by_its_cp1(notes):
    a = notes[0]
    assert note_id_of(a["ck1"]) == a["notePubkey"]
    assert note_id_of(f"  {a['ck1'].upper()}  ") == a["notePubkey"]
    assert note_lookup_of(a["ck1"]) == a["cp1"]


def test_anything_else_has_no_id(notes, cert):
    a = notes[0]
    corrupted = a["ck1"][:-1] + ("p" if a["ck1"].endswith("q") else "q")
    for bad in ["", "zz", "11" * 31, a["cp1"], cert["cs1"], corrupted, None, 42]:
        assert note_id_of(bad) is None
        if isinstance(bad, str):
            assert note_lookup_of(bad) is None


def test_one_key_reproduces_one_ck1_per_mint(notes):
    # all-zero auxiliary input: a wallet restored from its seed re-signs every
    # note it ever held to the same string, for the same mint
    sk = bytes.fromhex(notes[0]["noteSecretKey"])
    first = sign_note_ownership(sk, DOMAIN)
    assert first == sign_note_ownership(sk, "https://MINT.EXAMPLE:3338/w")
    assert encode_ck1(first) == notes[0]["ck1"]
    assert sign_note_ownership(sk, "elsewhere.example") != first
    with pytest.raises(ProtocolError):
        sign_note_ownership(sk, "")


def test_a_legacy_ck1_stays_readable_for_rotation(notes):
    a = notes[0]
    legacy = legacy_ck1(a["noteSecretKey"])
    assert len(decode_ck1(legacy)) == 65
    assert is_ck1(legacy)
    assert note_id_of(legacy) == a["notePubkey"]
    assert note_lookup_of(legacy) == a["cp1"]
    # read, never written: the encoder only takes the current 96 bytes
    with pytest.raises(ProtocolError):
        encode_ck1(decode_ck1(legacy))
    # it names no mint, so it reads the same at any, and says it is old
    for domain in (DOMAIN, "elsewhere.example"):
        verified = verify_spend(legacy, domain)
        assert verified is not None and verified.legacy
        assert verified.output_key.hex() == a["notePubkey"]


@pytest.mark.parametrize("make", [raw_message_ck1, digest_message_ck1], ids=["raw", "sha256"])
def test_a_fixed_message_ck1_stays_readable_for_rotation(notes, make):
    # Both were current once: over the raw 9-byte "LNURLcash" before
    # 2026-09-16, then over its sha256 until spends moved onto the sighash.
    # sign_note_ownership makes neither anymore, but a note carrying one must
    # stay redeemable, and say it is old so a wallet rotates it.
    a, b = notes[0], notes[1]
    payload = make(bytes.fromhex(a["noteSecretKey"]))
    assert payload != sign_note_ownership(bytes.fromhex(a["noteSecretKey"]), DOMAIN)
    owner = recover_note_ownership_pubkey(payload, DOMAIN)
    assert owner is not None and owner.legacy
    assert owner.pubkey_x_only == bytes.fromhex(a["notePubkey"])
    assert note_id_of(encode_ck1(payload)) == a["notePubkey"]
    # and its signature is not simply accepted for any message: moved onto
    # another key, it verifies under no scheme
    other = decode_ck1(b["ck1"])
    assert recover_note_ownership_pubkey(other[:32] + payload[32:], DOMAIN) is None
    # the current ck1 is not mistaken for an old one
    current = recover_note_ownership_pubkey(decode_ck1(a["ck1"]), DOMAIN)
    assert current is not None and not current.legacy


def test_the_signed_message_is_over_the_key_for_a_ck1(notes):
    a = notes[0]
    assert note_signature_message(a["ck1"], 21000) == f"LNURLcash:21000:{a['notePubkey']}"
    with pytest.raises(ProtocolError):
        note_signature_message("not a k1", 21000)
    with pytest.raises(ProtocolError):
        note_signature_message(a["cp1"], 21000)


# ---- note URLs and lookups ----


def test_a_note_url_may_carry_a_ck1_but_not_a_cp1(notes, cert):
    a = notes[0]
    url = f"https://mint.example/w?k1={a['ck1']}&amount=1000&sig={cert['cs1']}"
    assert resolve_note_input(url) == url
    assert resolve_note_input(f"lnurlw://MINT.EXAMPLE/w?k1={a['ck1']}") is not None
    # signed for one mint, it is no note at another
    assert resolve_note_input(f"https://elsewhere.example/w?k1={a['ck1']}") is None
    # a cp1 is the note's public name: a URL carrying one spends nothing
    assert resolve_note_input(f"https://mint.example/w?k1={a['cp1']}&amount=1000") is None


def _echoing(part2: dict, k1: str) -> dict:
    """An informational GET's answer, echoing ``k1``."""
    return {
        "tag": "withdrawRequest",
        "callback": CB,
        "k1": k1,
        "maxWithdrawable": 21000,
        "mintPubkey": part2["mint"]["mintPubkey"],
    }


def test_a_mint_echoing_another_spelling_of_the_same_note_is_believed(part2, notes):
    # Asked with a's ck1, the mint echoes a's legacy ck1. That proves the same
    # key, so it names the same note, and refusing it would report a live note
    # as redeemed elsewhere.
    a = notes[0]
    legacy = legacy_ck1(a["noteSecretKey"])
    request = note_info_request(f"https://mint.example/w?k1={a['ck1']}&amount=21000")
    info = request.parse(_echoing(part2, legacy))
    assert note_id_of(info.k1) == a["notePubkey"]
    assert info.max_withdrawable == 21000


@pytest.mark.parametrize("make", [raw_message_ck1, digest_message_ck1], ids=["raw", "sha256"])
def test_a_mint_echoing_an_older_ck1_for_the_same_note_is_believed(part2, notes, make):
    a = notes[0]
    older = encode_ck1(make(bytes.fromhex(a["noteSecretKey"])))
    request = note_info_request(f"https://mint.example/w?k1={a['ck1']}&amount=21000")
    info = request.parse(_echoing(part2, older))
    assert note_id_of(info.k1) == a["notePubkey"]


def test_a_mint_echoing_a_different_notes_ck1_is_still_refused(part2, notes):
    # the check exists for exactly this: a different note, however well formed
    a, b = notes[0], notes[1]
    request = note_info_request(f"https://mint.example/w?k1={a['ck1']}&amount=21000")
    with pytest.raises(ProtocolError, match="different k1"):
        request.parse(_echoing(part2, b["ck1"]))
    # and the right key under a signature that opens nothing is not the note
    forged = bytearray(decode_ck1(a["ck1"]))
    forged[40] ^= 0xFF
    with pytest.raises(ProtocolError, match="different k1"):
        request.parse(_echoing(part2, encode_ck1(bytes(forged))))


def test_every_note_is_looked_up_by_p(notes):
    a = notes[0]
    by_key = query(build_note_info_url_by_hash("https://mint.example/w", a["cp1"]))
    assert by_key == {"p": [a["cp1"]]}
    # a bearer note's h is the cp1 slot's short form, and goes in the same place
    by_hash = query(build_note_info_url_by_hash("https://mint.example/w", hash_k1(K1)))
    assert by_hash == {"p": [hash_k1(K1)]}
    # the ck1 is the bearer secret: naming it here would defeat the point
    with pytest.raises(ProtocolError):
        build_note_info_url_by_hash("https://mint.example/w", a["ck1"])


def test_a_lookup_by_cp1_brings_back_a_certificate_that_verifies(part2, notes, cert):
    a = notes[0]
    request = note_info_by_hash_request("https://mint.example/w", note_lookup_of(a["ck1"]))
    assert query(request.url) == {"p": [a["cp1"]]}
    info = request.parse(
        {
            "tag": "withdrawRequest",
            "callback": CB,
            "minWithdrawable": cert["amountMsat"],
            "maxWithdrawable": cert["amountMsat"],
            "mintPubkey": part2["mint"]["mintPubkey"],
            "sig": cert["cs1"],
        }
    )
    assert info.signature == cert["cs1"]
    assert (
        verify_note_signature(
            a["ck1"], DOMAIN, info.max_withdrawable, info.signature, info.mint_pubkey
        )
        is Certification.CERTIFIED_OVER_Q
    )


# ---- mutations ----


def test_rotate_a_ck1_into_a_cp1_sent_as_p1(notes, cert):
    a, b = notes[0], notes[1]
    request = rotate_request_with_hash(CB, a["ck1"], b["cp1"])
    assert query(request.url) == {"k1": [a["ck1"]], "p1": [b["cp1"]]}
    assert request.replayable is True
    assert request.parse({"status": "OK", "sig": cert["cs1"]}).signature == cert["cs1"]


def test_a_bearer_output_goes_as_p1_too(notes):
    # a bearer note's h is the cp1 slot's short form
    request = rotate_request_with_hash(CB, notes[0]["ck1"], hash_k1(K1))
    assert query(request.url) == {"k1": [notes[0]["ck1"]], "p1": [hash_k1(K1)]}


def test_split_names_both_outputs_p1_and_p2_whatever_they_are(notes):
    a, b, c = notes[0], notes[1], notes[2]
    mixed = query(split_request_with_hash(CB, [a["ck1"]], 5000, b["cp1"], hash_k1(K1)).url)
    assert mixed == {
        "k1": [a["ck1"]],
        "amount": ["5000"],
        "p1": [b["cp1"]],
        "p2": [hash_k1(K1)],
    }
    keys = query(split_request_with_hash(CB, [a["ck1"]], 5000, b["cp1"], c["cp1"]).url)
    assert keys["p1"] == [b["cp1"]] and keys["p2"] == [c["cp1"]]
    assert "h" not in keys and "h2" not in keys


def test_one_merge_takes_a_part1_secret_and_a_part2_note(notes):
    a, c = notes[0], notes[2]
    request = merge_request_with_hash(CB, [K1, a["ck1"]], c["cp1"])
    assert query(request.url) == {"k1": [K1, a["ck1"]], "p1": [c["cp1"]]}


# What each output is owed. LUD-25 has a mint certify every note (a SHOULD).
# An output named by cp1 is owed its cs1 whatever the policy says, because
# offline verification is the reason to name it so. One named by a bearer h
# may come back uncertified from a mint with no signer, unless the caller asks
# for require_signatures.

_EVERY_POLICY = [
    None,
    Policy(require_signatures=False),
    Policy(require_signatures=True),
    Policy(require_signatures=False, require_mint_pubkey=False),
]
_PART1_SIG = "ab" * 65


def _with_policy(build, *args, policy):
    return build(*args) if policy is None else build(*args, policy)


@pytest.mark.parametrize("policy", _EVERY_POLICY, ids=repr)
def test_an_uncertified_cp1_output_is_unverifiable_whatever_the_policy(notes, policy):
    a, b = notes[0], notes[1]
    for request in (
        _with_policy(rotate_request_with_hash, CB, a["ck1"], b["cp1"], policy=policy),
        # the same key in upper case is still sent as p1, so still owed a cs1
        _with_policy(
            rotate_request_with_hash, CB, a["ck1"], b["cp1"].upper(), policy=policy
        ),
        _with_policy(merge_request_with_hash, CB, [K1, a["ck1"]], b["cp1"], policy=policy),
        _with_policy(
            split_request_with_hash, CB, [a["ck1"]], 5000, b["cp1"], hash_k1(K1),
            policy=policy,
        ),
    ):
        for body in ({"status": "OK"}, {"status": "OK", "sig": ""}):
            with pytest.raises(UnverifiableNote):
                request.parse(body)


@pytest.mark.parametrize("policy", _EVERY_POLICY, ids=repr)
def test_a_cp1_change_without_sig2_is_unverifiable_whatever_the_policy(
    notes, cert, policy
):
    a, b, c = notes[0], notes[1], notes[2]
    # the change is no lesser note than the first output
    behind_a_hash = _with_policy(
        split_request_with_hash, CB, [a["ck1"]], 5000, hash_k1(K1), c["cp1"],
        policy=policy,
    )
    with pytest.raises(UnverifiableNote):
        behind_a_hash.parse({"status": "OK", "sig": _PART1_SIG})
    both_keys = _with_policy(
        split_request_with_hash, CB, [a["ck1"]], 5000, b["cp1"], c["cp1"],
        policy=policy,
    )
    with pytest.raises(UnverifiableNote):
        both_keys.parse({"status": "OK", "sig": cert["cs1"]})
    certified = both_keys.parse({"status": "OK", "sig": cert["cs1"], "sig2": cert["cs1"]})
    assert certified.signature == certified.change_signature == cert["cs1"]


def test_a_hash_change_beside_a_certified_cp1_is_a_plain_note(notes, cert):
    a, b = notes[0], notes[1]
    request = split_request_with_hash(CB, [a["ck1"]], 5000, b["cp1"], hash_k1(K1))
    result = request.parse({"status": "OK", "sig": cert["cs1"]})
    assert result.signature == cert["cs1"]
    assert result.change_signature is None
    # unless the caller asks for the Part 1 signature over the hash
    strict = split_request_with_hash(
        CB, [a["ck1"]], 5000, b["cp1"], hash_k1(K1), Policy(require_signatures=True)
    )
    with pytest.raises(UnverifiableNote):
        strict.parse({"status": "OK", "sig": cert["cs1"]})


def test_an_uncertified_cp1_hands_back_nothing_it_never_held(notes):
    """The caller named that output and holds its key; this library never saw
    it, so there is nothing for the exception to carry. It is still raised,
    through the client, as the landed mutation it is."""
    a, b = notes[0], notes[1]

    def answer(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "OK"})

    with httpx.Client(transport=httpx.MockTransport(answer)) as http:
        with pytest.raises(UnverifiableNote) as raised:
            LnurlcashClient(client=http).rotate_note_with_hash(CB, a["ck1"], b["cp1"])
    assert new_secrets_of(raised.value) == []


def test_a_ck1_melts_like_any_k1(notes):
    request = melt_request(CB, notes[0]["ck1"], "lnbc210n1pjqrstuvwxyz")
    assert query(request.url)["k1"] == [notes[0]["ck1"]]


def test_the_client_sends_a_ck1_and_a_cp1_exactly_as_built(notes, cert):
    a, b = notes[0], notes[1]
    seen: list[httpx.URL] = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(request.url)
        return httpx.Response(200, json={"status": "OK", "sig": cert["cs1"]})

    with httpx.Client(transport=httpx.MockTransport(answer)) as http:
        result = LnurlcashClient(client=http).rotate_note_with_hash(CB, a["ck1"], b["cp1"])
    assert result.signature == cert["cs1"]
    assert [str(url) for url in seen] == [rotate_request_with_hash(CB, a["ck1"], b["cp1"]).url]


# ---- minting to a key ----


def test_a_cp1_is_minted_to_as_the_comment_alone(notes):
    a = notes[0]
    request = mint_invoice_request_with_hash(PAY_CB, 21000, a["cp1"].upper())
    assert query(request.url) == {"amount": ["21000"], "comment": [a["cp1"]]}


def test_a_hash_is_minted_to_as_comment_and_h_as_before():
    request = mint_invoice_request_with_hash(PAY_CB, 21000, hash_k1(K1))
    assert query(request.url) == {
        "amount": ["21000"],
        "comment": [hash_k1(K1)],
        "h": [hash_k1(K1)],
    }


def test_anything_else_is_refused_before_an_invoice_is_asked_for(notes, cert):
    # a ck1 above all: minting to the bearer secret would publish it
    for bad in [notes[0]["ck1"], cert["cs1"], "cx1", ""]:
        with pytest.raises(RequestRefused):
            mint_invoice_request_with_hash(PAY_CB, 21000, bad)


# ---- the encodings ----


def test_the_five_types_never_pass_for_one_another(part2, notes, cert):
    a, cx1, cw1 = notes[0], part2["branches"][0]["cx1"], bearer_cw1(K1)
    checks = (is_cp1, is_ck1, is_cw1, is_cs1_with_amount, is_cx1)
    assert [check(a["cp1"]) for check in checks] == [True, False, False, False, False]
    assert [check(a["ck1"]) for check in checks] == [False, True, False, False, False]
    assert [check(cw1) for check in checks] == [False, False, True, False, False]
    assert [check(cert["cs1"]) for check in checks] == [False, False, False, True, False]
    assert [check(cx1) for check in checks] == [False, False, False, False, True]
    # and a bearer preimage or h is none of them
    assert [check(K1) for check in checks] == [False] * 5


def test_an_off_curve_cp1_names_no_note():
    # x = 5 has no point on secp256k1: a note there could never be spent
    off_curve = encode_cp1((5).to_bytes(32, "big"))
    assert decode_cp1(off_curve) is None and not is_cp1(off_curve)
    with pytest.raises(RequestRefused):
        mint_invoice_request_with_hash(PAY_CB, 21000, off_curve)


def test_no_90_character_limit(notes, cert, part2):
    # BIP-173's limit is for segwit addresses; LUD-25 does not adopt it
    for value in (notes[0]["ck1"], cert["cs1"], part2["branches"][0]["cx1"]):
        assert len(value) > 90
    assert decode_ck1(notes[0]["ck1"]) is not None


def test_a_bech32_checksum_is_refused_for_being_bech32(notes):
    # Not merely "some checksum failed": the same payload under the other
    # constant decodes as bech32 and is refused as bech32m.
    pk = bytes.fromhex(notes[0]["notePubkey"])
    plain = bech32.encode("cp", pk)
    assert bech32.decode(plain) == ("cp", pk)
    assert decode_cp1(plain) is None
    assert decode_cp1(bech32.encode("cp", pk, constant=bech32.BECH32M)) == pk


def test_upper_case_is_the_same_string_and_mixed_case_is_not(notes):
    cp1 = notes[0]["cp1"]
    assert decode_cp1(cp1.upper()) == decode_cp1(cp1)
    assert decode_cp1(cp1[:10].upper() + cp1[10:]) is None


def test_non_zero_padding_is_refused(notes):
    # 32 bytes is 52 five-bit groups with 4 bits of padding. Set one of those
    # bits and checksum it properly, and the string is well-formed bech32m that
    # decodes to nothing.
    words = bech32.convertbits(bytes.fromhex(notes[0]["notePubkey"]), 8, 5)
    words[-1] |= 1
    checksum = bech32._create_checksum("cp", words, bech32.BECH32M)
    padded = "cp1" + "".join(bech32.CHARSET[w] for w in words + checksum)
    assert decode_cp1(padded) is None


def test_decoders_return_none_rather_than_raise():
    for bad in [None, 42, b"cp1", "", "cp1", "1", "cp1éééééé", "cp1 x"]:
        for decode in (
            decode_cp1,
            decode_ck1,
            decode_cs1,
            decode_cs1_with_amount,
            decode_any_cs1,
            decode_cx1,
        ):
            assert decode(bad) is None


def test_encoders_refuse_a_payload_of_the_wrong_length():
    with pytest.raises(ProtocolError):
        encode_cp1(bytes(33))
    with pytest.raises(ProtocolError):
        encode_ck1(bytes(64))
    with pytest.raises(ProtocolError):
        encode_cs1_with_amount(1, bytes(64))
    with pytest.raises(ProtocolError):
        encode_cx1(bytes(32), bytes(31))


@pytest.mark.parametrize("amount", [0, 1, 99, 100, 21_000, 2**63 - 1])
def test_amount_bearing_cs1_boundaries(amount):
    signature = bytes(65)
    encoded = encode_cs1_with_amount(amount, signature)
    assert decode_cs1_with_amount(encoded) == Cs1(amount, signature)


@pytest.mark.parametrize("amount", [-1, 1.0, True, None])
def test_amount_bearing_cs1_requires_a_non_negative_integer(amount):
    with pytest.raises(ProtocolError):
        encode_cs1_with_amount(amount, bytes(65))


def test_lnurl_decoding_is_untouched_by_bech32m():
    # LUD-01 is bech32, and a bech32m string must not sneak in through it
    lnurl = bech32.encode("lnurl", b"https://mint.example/w")
    assert bech32.decode(lnurl) == ("lnurl", b"https://mint.example/w")
    assert bech32.decode(lnurl, constant=bech32.BECH32M) is None


# ---- the key tweak ----


class _Digest:
    def __init__(self, value: bytes) -> None:
        self._value = value

    def digest(self) -> bytes:
        return self._value


def _branch(part2: dict) -> tuple[bytes, bytes, bytes]:
    branch = part2["branches"][0]
    node = cash_node_from_hex(branch["addressNode"])
    return node.private_key, bytes.fromhex(branch["branchPubkey"]), node.chain_code


def test_the_index_is_a_uint32(part2):
    sk, pk, chain = _branch(part2)
    for bad in [-1, 2**32, 1.5, True, "0"]:
        with pytest.raises(ProtocolError):
            derive_note_pubkey(pk, chain, bad)
        with pytest.raises(ProtocolError):
            derive_note_secret_key(sk, chain, bad)


def test_a_tweak_at_or_above_n_is_reduced_mod_n(part2, monkeypatch):
    # A ~2^-128 event nobody will meet, but the spec requires t mod n, and
    # lnurl-wallet reduces it: 2^256 - 1 derives exactly what 2^256 - 1 - n does
    sk, pk, chain = _branch(part2)
    reduced = (2**256 - 1 - _CURVE_N).to_bytes(32, "big")
    monkeypatch.setattr(recoverable, "sha256", lambda _data: _Digest(reduced))
    want_pk, want_sk = derive_note_pubkey(pk, chain, 0), derive_note_secret_key(sk, chain, 0)
    monkeypatch.setattr(recoverable, "sha256", lambda _data: _Digest(b"\xff" * 32))
    assert derive_note_pubkey(pk, chain, 0) == want_pk
    assert derive_note_secret_key(sk, chain, 0) == want_sk
    assert PrivateKey(want_sk).public_key.format(compressed=True)[1:] == want_pk


def test_a_tweak_that_lands_on_zero_is_refused(part2, monkeypatch):
    # t = n - p puts the note key at zero and its point at infinity: the other
    # way an index is unusable, and the same answer
    sk, pk, chain = _branch(part2)
    p = int.from_bytes(sk, "big")
    even = PrivateKey(sk).public_key.format(compressed=True)[0] == 0x02
    t = _CURVE_N - (p if even else _CURVE_N - p)
    monkeypatch.setattr(recoverable, "sha256", lambda _data: _Digest(t.to_bytes(32, "big")))
    with pytest.raises(ProtocolError, match="next index"):
        derive_note_pubkey(pk, chain, 0)
    with pytest.raises(ProtocolError, match="next index"):
        derive_note_secret_key(sk, chain, 0)


def test_a_branch_key_off_the_curve_is_refused(part2):
    _, _, chain = _branch(part2)
    # x = 5 has no point on secp256k1
    with pytest.raises(ProtocolError):
        derive_note_pubkey((5).to_bytes(32, "big"), chain, 0)


def test_a_bad_branch_private_key_is_refused(part2):
    _, _, chain = _branch(part2)
    for bad in [bytes(32), _CURVE_N.to_bytes(32, "big"), bytes(31)]:
        with pytest.raises(ProtocolError):
            derive_note_secret_key(bad, chain, 0)


# ---- ownership signatures ----


def test_a_truncated_or_corrupted_signature_is_not_the_note(notes):
    a = notes[0]
    pk = bytes.fromhex(a["notePubkey"])
    payload = decode_ck1(a["ck1"])
    assert len(payload) == 96
    owner = recover_note_ownership_pubkey(payload, DOMAIN)
    assert owner is not None and owner.pubkey_x_only == pk and not owner.legacy
    assert recover_note_ownership_pubkey(payload[:95], DOMAIN) is None
    assert recover_note_ownership_pubkey(payload[:64], DOMAIN) is None
    assert recover_note_ownership_pubkey(b"", DOMAIN) is None
    assert recover_note_ownership_pubkey(bytes([0xFF]) * 96, DOMAIN) is None
    assert recover_note_ownership_pubkey("not bytes", DOMAIN) is None
    for at in (10, 40, 90):
        corrupted = bytearray(payload)
        corrupted[at] ^= 0xFF
        recovered = recover_note_ownership_pubkey(bytes(corrupted), DOMAIN)
        assert recovered is None or recovered.pubkey_x_only != pk
    # a key and a valid signature by a different key is not a proof
    b = decode_ck1(notes[1]["ck1"])
    assert recover_note_ownership_pubkey(payload[:32] + b[32:], DOMAIN) is None
    # and a current ck1 at another mint opens nothing
    assert recover_note_ownership_pubkey(payload, "elsewhere.example") is None


def test_signing_refuses_a_key_that_is_not_one():
    for bad in [bytes(32), bytes(31), b"\x01", _CURVE_N.to_bytes(32, "big")]:
        with pytest.raises(ProtocolError):
            sign_note_ownership(bad, DOMAIN)


# ---- derivation entry points ----


def test_the_master_node_is_bip32s_own(part2):
    # BIP-32 test vector 1: its published seed, and the master node conformance
    # carries for it
    master = derive_cash_master(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    steps = load_vectors("cash-derivation.json")["bip32Vector1"]
    assert master.private_key.hex() + master.chain_code.hex() == steps[0]["node"]

    seed = bytes.fromhex(part2["branches"][0]["seedHex"])
    root = derive_cash_child(derive_cash_master(seed), 139 + 0x80000000)
    assert root == derive_cash_root(seed)


def test_a_nostr_seed_needs_a_32_byte_key():
    for bad in [bytes(31), bytes(33), "00" * 32]:
        with pytest.raises(ProtocolError):
            derive_nostr_cash_seed(bad)


def test_a_cx1_round_trips(part2):
    branch = part2["branches"][0]
    cx1 = decode_cx1(branch["cx1"])
    assert cx1 is not None
    assert encode_cx1(cx1.pubkey_x_only, cx1.chain_code) == branch["cx1"]
    assert encode_cp1(derive_note_pubkey(cx1.pubkey_x_only, cx1.chain_code, 0)) == (
        branch["notes"][0]["cp1"]
    )
