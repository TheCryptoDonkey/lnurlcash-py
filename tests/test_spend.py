"""spends.json: what opens a note, graded field by field.

Bearer notes of both parities from preimage to cw1, one key's ck1 at several
mints and the cross-mint spends that must fail, a three-leaf script tree, a
CHECKSIG leaf's script-path sighash, the leaf and time rules, and the
malformed values that must name no note.
"""

from __future__ import annotations

import hashlib
from urllib.parse import parse_qs, urlparse

import pytest
from coincurve import PrivateKey, PublicKeyXOnly

from conftest import load_vectors
from lnurlcash_kit import (
    NUMS_KEY,
    TAPLEAF_VERSION,
    Cw1,
    ProtocolError,
    bearer_cw1,
    bearer_leaf,
    bearer_note,
    bearer_note_id,
    build_note_info_url_by_hash,
    check_leaf_policy,
    check_time_claim,
    decode_cp1,
    decode_cw1,
    decode_spend,
    encode_ck1,
    encode_cp1,
    encode_cw1,
    is_cp1,
    key_path_sighash,
    note_id_of,
    output_key_of,
    output_key_of_cw1,
    script_path_sighash,
    sign_note_ownership,
    spend_domain_of,
    spend_prevout,
    spend_sig_msg,
    tap_leaf_hash,
    taproot_tweak,
    verify_spend,
)
from lnurlcash_kit.protocol import rotate_request_with_hash

_SPENDS = "spends.json"


def _spends() -> dict:
    return load_vectors(_SPENDS)


def _tagged(tag: str, *parts: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + b"".join(parts)).digest()


def test_spends_is_the_format_this_suite_reads():
    assert _spends()["version"] == 1
    assert NUMS_KEY.hex() == _spends()["nums"]


def test_every_op_success_and_nothing_else_is_refused():
    conventions = _spends()["conventions"]
    claims = conventions["timeClaims"]
    assert claims["locktimeThreshold"] == 500_000_000
    assert claims["sequenceDisableFlag"] == 1 << 31
    assert claims["sequenceTypeFlag"] == 1 << 22
    assert claims["sequenceValueMask"] == 0xFFFF
    assert claims["granularitySeconds"] == 512
    success: set[int] = set()
    for entry in conventions["leafPolicy"]["opSuccess"]:
        if isinstance(entry, int):
            success.add(entry)
        else:
            low, high = (int(part) for part in entry.split("-"))
            success.update(range(low, high + 1))
    for op in range(256):
        # pushes consume what follows them, so each opcode stands alone
        if 0x01 <= op <= 0x4E:
            continue
        refused = check_leaf_policy(TAPLEAF_VERSION, bytes([op])) is not None
        assert refused is (op in success), op


@pytest.mark.parametrize("bearer", _spends()["bearers"], ids=lambda b: b["name"])
def test_bearer_note(bearer):
    preimage = bytes.fromhex(bearer["preimage"])
    h = hashlib.sha256(preimage).digest()
    assert h.hex() == bearer["h"]
    leaf = bearer_leaf(h)
    assert leaf.hex() == bearer["leaf"]
    leaf_hash = tap_leaf_hash(leaf)
    assert leaf_hash.hex() == bearer["tapleafHash"]
    assert _tagged("TapTweak", NUMS_KEY, leaf_hash).hex() == bearer["tweak"]
    q, odd = taproot_tweak(NUMS_KEY, leaf_hash)
    assert q.hex() == bearer["Q"] and odd is (bearer["parity"] == 1)
    note = bearer_note(h)
    assert note.control_block.hex() == bearer["controlBlock"]
    assert encode_cp1(note.output_key) == bearer["cp1"]
    assert bearer_cw1(bearer["preimage"]) == bearer["cw1"]
    assert decode_cw1(bearer["cw1"]) == Cw1(0, 0xFFFFFFFF, leaf, note.control_block, (preimage,))
    assert output_key_of_cw1(bearer["cw1"]).hex() == bearer["Q"]
    assert bearer_note_id(bearer["h"]) == bearer["Q"]
    # one note, one spend, three spellings, no signature and so no mint
    for spend in (bearer["preimage"], bearer["preimage"].upper(), bearer["cw1"]):
        verified = verify_spend(spend, "any.example")
        assert verified is not None and verified.output_key.hex() == bearer["Q"]
        assert not verified.legacy and not verified.unevaluated


def test_bearer_notes_cover_both_parities():
    assert {b["parity"] for b in _spends()["bearers"]} == {0, 1}


def test_key_path_spends():
    vectors = _spends()["keyPath"]
    key = bytes.fromhex(vectors["secretKey"])
    q = bytes.fromhex(vectors["Q"])
    assert PrivateKey(key).public_key_xonly.format() == q
    assert encode_cp1(q) == vectors["cp1"]
    by_domain = {}
    for spend in vectors["spends"]:
        by_domain[spend["domain"].lower()] = spend["ck1"]
        assert spend_domain_of(spend["domain"]) == spend["normalisedDomain"]
        assert spend_prevout(spend["domain"]).hex() == spend["prevoutTxid"]
        assert key_path_sighash(q, spend["domain"]).hex() == spend["sighash"]
        payload = sign_note_ownership(key, spend["domain"])
        assert payload[32:].hex() == spend["signature"]
        assert encode_ck1(payload) == spend["ck1"]
        verified = verify_spend(spend["ck1"], spend["domain"])
        assert verified is not None and verified.output_key == q and not verified.legacy
    for case in vectors["crossDomain"]:
        ck1 = by_domain[case["signedFor"].lower()]
        assert (verify_spend(ck1, case["verifiedAt"]) is not None) is case["valid"], case["why"]


@pytest.mark.parametrize("case", _spends()["domains"], ids=lambda c: c["url"])
def test_the_domain_of_a_url(case):
    assert spend_domain_of(case["url"]) == case["domain"]


def test_a_script_tree():
    tree = _spends()["tree"]
    internal = bytes.fromhex(tree["internalKey"])
    assert PrivateKey(bytes.fromhex(tree["internalSecretKey"])).public_key_xonly.format() == internal
    assert tree["shape"] == "root = branch(branch(leaves[0], leaves[1]), leaves[2])"

    def branch(a: bytes, b: bytes) -> bytes:
        return _tagged("TapBranch", *sorted((a, b)))

    hashes = []
    for leaf in tree["leaves"]:
        leaf_hash = tap_leaf_hash(bytes.fromhex(leaf["script"]), leaf["version"])
        assert leaf_hash.hex() == leaf["tapleafHash"]
        hashes.append(leaf_hash)
    root = branch(branch(hashes[0], hashes[1]), hashes[2])
    assert root.hex() == tree["merkleRoot"]
    assert _tagged("TapTweak", internal, root).hex() == tree["tweak"]
    q, odd = taproot_tweak(internal, root)
    assert q.hex() == tree["Q"] and odd is (tree["parity"] == 1)
    assert encode_cp1(q) == tree["cp1"]

    domain = tree["keyPath"]["domain"]
    for leaf in tree["leaves"]:
        spend = Cw1(
            0,
            0xFFFFFFFF,
            bytes.fromhex(leaf["script"]),
            bytes.fromhex(leaf["controlBlock"]),
            tuple(bytes.fromhex(item) for item in leaf["witness"]),
        )
        assert encode_cw1(spend) == leaf["cw1"]
        # every leaf commits to the one Q, whatever the leaf rules say of it
        assert output_key_of(spend.script, spend.control_block) == q
        verified = verify_spend(leaf["cw1"], domain)
        if leaf["verdict"] == "accept":
            assert verified is not None and verified.output_key == q
        else:
            assert leaf["verdict"] == "reject"
            assert verified is None, leaf["reason"]

    key_path = tree["keyPath"]
    tweaked = bytes.fromhex(key_path["tweakedSecretKey"])
    assert PrivateKey(tweaked).public_key_xonly.format() == q
    assert key_path_sighash(q, domain).hex() == key_path["sighash"]
    payload = sign_note_ownership(tweaked, domain)
    assert payload[32:].hex() == key_path["signature"]
    assert encode_ck1(payload) == key_path["ck1"]
    verified = verify_spend(key_path["ck1"], domain)
    assert verified is not None and verified.output_key == q


def test_a_checksig_leaf():
    case = _spends()["checksig"]
    pubkey = bytes.fromhex(case["pubkey"])
    assert PrivateKey(bytes.fromhex(case["secretKey"])).public_key_xonly.format() == pubkey
    leaf = bytes.fromhex(case["leaf"])
    assert leaf == b"\x20" + pubkey + b"\xac"
    q = output_key_of(leaf, bytes.fromhex(case["controlBlock"]))
    assert q is not None and q.hex() == case["Q"]
    assert encode_cp1(q) == case["cp1"]
    for spend in case["spends"]:
        sig_msg = spend_sig_msg(q, case["domain"], spend["locktime"], spend["sequence"], leaf)
        assert sig_msg.hex() == spend["sigMsg"]
        assert len(sig_msg) == 211
        sighash = script_path_sighash(q, case["domain"], leaf, spend["locktime"], spend["sequence"])
        assert sighash.hex() == spend["sighash"]
        assert PublicKeyXOnly(pubkey).verify(bytes.fromhex(spend["signature"]), sighash)
        decoded = decode_cw1(spend["cw1"])
        assert decoded == Cw1(
            spend["locktime"],
            spend["sequence"],
            leaf,
            bytes.fromhex(case["controlBlock"]),
            (bytes.fromhex(spend["signature"]),),
        )
        assert encode_cw1(decoded) == spend["cw1"]
        # a CHECKSIG leaf is not one this library runs: structure and Q only
        verified = verify_spend(spend["cw1"], case["domain"])
        assert verified is not None and verified.output_key == q and verified.unevaluated


@pytest.mark.parametrize("case", _spends()["timeClaims"], ids=lambda c: c["name"])
def test_time_claims(case):
    reason = check_time_claim(case["locktime"], case["sequence"], case["now"], case["lockedAt"])
    assert case["verdict"] in ("accept", "reject")
    assert (reason is None) is (case["verdict"] == "accept"), case["why"]


@pytest.mark.parametrize("case", _spends()["leafPolicy"], ids=lambda c: c["name"])
def test_leaf_policy(case):
    reason = check_leaf_policy(case["version"], bytes.fromhex(case["script"]))
    assert case["verdict"] in ("allowed", "refused")
    assert (reason is None) is (case["verdict"] == "allowed"), case["why"]


@pytest.mark.parametrize("case", _spends()["malformedCw1"], ids=lambda c: c["name"])
def test_a_malformed_cw1_names_no_note(case):
    assert output_key_of_cw1(case["value"]) is None, case["why"]
    assert decode_spend(case["value"]) is None
    assert note_id_of(case["value"]) is None
    assert verify_spend(case["value"], "mint.example") is None


@pytest.mark.parametrize("case", _spends()["invalidCp1"], ids=lambda c: c["why"])
def test_an_off_curve_cp1_names_no_note(case):
    assert encode_cp1(bytes.fromhex(case["x"])) == case["cp1"]
    assert decode_cp1(case["cp1"]) is None and not is_cp1(case["cp1"])
    with pytest.raises(ProtocolError):
        build_note_info_url_by_hash("https://mint.example/w", case["cp1"])


@pytest.mark.parametrize("case", _spends()["shortForms"], ids=lambda c: c["Q"][:12])
def test_short_forms(case):
    # the cp1 slot: hex h and its cp1 name one note
    assert bearer_note_id(case["cp1Slot"]["hex"]) == case["Q"]
    assert decode_cp1(case["cp1Slot"]["sameAs"]).hex() == case["Q"]
    # the k1 slot: the preimage and its cw1 are one spend
    assert bearer_cw1(case["k1Slot"]["hex"]) == case["k1Slot"]["sameAs"]
    for spend in (case["k1Slot"]["hex"], case["k1Slot"]["sameAs"]):
        assert note_id_of(spend) == case["Q"]
    # either spelling of an output goes to the mint as p1
    for output in (case["cp1Slot"]["hex"], case["cp1Slot"]["sameAs"]):
        request = rotate_request_with_hash(
            "https://mint.example/w/cb", case["k1Slot"]["hex"], output
        )
        assert parse_qs(urlparse(request.url).query)["p1"] == [output]


def test_decoders_never_raise():
    for bad in [None, 42, "", "cw1", "cw1qqqqqq8llllsfyw4xk", "0" * 64 + "z", "ck1qqqqqq"]:
        assert decode_cw1(bad) is None  # type: ignore[arg-type]
        if isinstance(bad, str) or bad is None:
            decode_spend(bad)  # type: ignore[arg-type]
            verify_spend(bad, "mint.example")  # type: ignore[arg-type]
            output_key_of_cw1(bad)  # type: ignore[arg-type]
