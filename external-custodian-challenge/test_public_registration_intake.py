import json

import public_registration_intake as I


def block(payload):
    return "```json\n" + json.dumps(payload) + "\n```"


def valid(login="alice", role="selector_labeler"):
    return {
        "github_login": login,
        "role": role,
        "affiliation": "independent",
        "conflict_disclosure": "none",
        "public_key_fingerprint": "",
        "protocol_freeze_hash": I.PROTOCOL_FREEZE_HASH,
        "attests_no_predictor_access": True,
    }


def record(comment_id, login, role, *, body=None, author_type="User"):
    return {
        "id": comment_id,
        "body": body if body is not None else block(valid(login, role)),
        "author_login": login,
        "author_type": author_type,
        "html_url": f"https://example.test/comments/{comment_id}",
        "created_at": "2026-08-06T00:00:00Z",
        "issue_number": 3,
    }


def test_valid_claim_is_only_identity_unverified():
    receipt = I.validate_claim(
        body=block(valid()),
        author_login="alice",
        author_type="User",
        comment_id=1,
        comment_url="https://example.test/1",
        created_at="now",
    )
    assert receipt["accepted"] is True
    assert receipt["disposition"] == "ACCEPTED_CLAIM_IDENTITY_UNVERIFIED"
    assert receipt["claim"]["identity_verified"] is False
    assert receipt["claim_boundary"]["external_authority"] is False


def test_author_mismatch_owner_and_bot_are_rejected():
    mismatch = I.validate_claim(
        body=block(valid("alice")),
        author_login="bob",
        author_type="User",
        comment_id=2,
        comment_url="u",
        created_at="now",
    )
    owner = I.validate_claim(
        body=block(valid("leehyen0")),
        author_login="leehyen0",
        author_type="User",
        comment_id=3,
        comment_url="u",
        created_at="now",
    )
    bot = I.validate_claim(
        body=block(valid("robot[bot]")),
        author_login="robot[bot]",
        author_type="Bot",
        comment_id=4,
        comment_url="u",
        created_at="now",
    )
    assert "COMMENT_AUTHOR_LOGIN_MISMATCH" in mismatch["problems"]
    assert "OWNER_SELF_CUSTODY_FORBIDDEN" in owner["problems"]
    assert "BOT_REGISTRATION_FORBIDDEN" in bot["problems"]


def test_private_material_and_self_verification_fields_are_rejected():
    private = valid()
    private["nonce"] = "do-not-publish"
    receipt = I.validate_claim(
        body=block(private),
        author_login="alice",
        author_type="User",
        comment_id=5,
        comment_url="u",
        created_at="now",
    )
    assert receipt["accepted"] is False
    assert any(x.startswith("PRIVATE_MATERIAL_FORBIDDEN") for x in receipt["problems"])
    assert any(x.startswith("UNEXPECTED_FIELDS") for x in receipt["problems"])


def test_exactly_one_fenced_block_is_required():
    payload = block(valid())
    for body in (
        "prefix\n" + payload,
        payload + "\nsuffix",
        payload + "\n" + payload,
        json.dumps(valid()),
    ):
        parsed, problems = I.parse_registration_comment(body)
        assert parsed is None
        assert problems == ["EXACTLY_ONE_FENCED_JSON_BLOCK_REQUIRED"]


def test_wrong_protocol_and_false_attestation_are_rejected():
    payload = valid()
    payload["protocol_freeze_hash"] = "0" * 64
    payload["attests_no_predictor_access"] = False
    receipt = I.validate_claim(
        body=block(payload),
        author_login="alice",
        author_type="User",
        comment_id=6,
        comment_url="u",
        created_at="now",
    )
    assert "PROTOCOL_FREEZE_HASH_MISMATCH" in receipt["problems"]
    assert "PREDICTOR_ACCESS_ATTESTATION_REQUIRED" in receipt["problems"]


def test_duplicate_login_is_fail_closed():
    registry = I.build_registry([
        record(1, "alice", "selector_labeler"),
        record(2, "alice", "reveal_auditor"),
    ])
    assert registry["accepted_claim_count"] == 1
    assert registry["receipts"][1]["disposition"] == "REJECTED_DUPLICATE_LOGIN"
    assert registry["syntactic_two_role_candidate"] is False


def test_two_distinct_role_claims_do_not_form_external_quorum():
    registry = I.build_registry([
        record(1, "alice", "selector_labeler"),
        record(2, "bob", "reveal_auditor"),
    ])
    assert registry["accepted_claim_count"] == 2
    assert registry["syntactic_two_role_candidate"] is True
    assert registry["external_quorum_formed"] is False
    assert registry["identity_independence_verified"] is False
    assert registry["independent_external_successes"] == 0


def test_invalid_comments_do_not_change_registry_authority():
    registry = I.build_registry([
        record(1, "leehyen0", "selector_labeler"),
        record(2, "alice", "selector_labeler", body="not-json"),
    ])
    assert registry["accepted_claim_count"] == 0
    assert registry["authority"] == "NULL_NO_EXTERNAL_REGISTRATION"
    assert registry["promotion"] is False
    assert registry["agi"] is False
    assert registry["asi"] is False
