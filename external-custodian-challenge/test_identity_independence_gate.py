import json

import identity_independence_promotion as gate
import process_identity_independence_review as proc
import public_registration_intake as registration


def fenced(payload):
    return "```json\n" + json.dumps(payload) + "\n```"


def raw(cid, login, body, issue, user_type="User", created=None):
    return {
        "id": cid,
        "body": body,
        "created_at": created or f"2026-08-07T00:00:{cid%60:02d}Z",
        "html_url": f"synthetic://{issue}/{cid}",
        "user": {"login": login, "type": user_type},
    }


def reg_body(login, role, affiliation="independent"):
    return fenced({
        "github_login": login,
        "role": role,
        "affiliation": affiliation,
        "conflict_disclosure": "none",
        "public_key_fingerprint": "",
        "protocol_freeze_hash": registration.PROTOCOL_FREEZE_HASH,
        "attests_no_predictor_access": True,
    })


def evidence_payload(login, role, receipt_hash, prefix):
    return {
        "event_type": "evidence_bundle",
        "protocol_freeze_hash": gate.REGISTRATION_PROTOCOL_FREEZE,
        "subject_login": login,
        "subject_role": role,
        "registration_receipt_hash": receipt_hash,
        "conflict_disclosure": "none",
        "evidence": [
            {"kind": "github_account_control", "artifact_sha256": prefix[0]*64, "public_locator": f"https://github.com/{login}"},
            {"kind": "non_github_identity_anchor", "artifact_sha256": prefix[1]*64, "public_locator": f"https://example.org/{login}"},
            {"kind": "evaluation_independence", "artifact_sha256": prefix[2]*64, "public_locator": ""},
        ],
    }


def bundle_hash(payload, cid):
    row = {
        "subject_login": payload["subject_login"],
        "subject_role": payload["subject_role"],
        "registration_receipt_hash": payload["registration_receipt_hash"],
        "conflict_disclosure": payload["conflict_disclosure"],
        "evidence": gate.canonical(payload["evidence"]),
        "source_comment_id": cid,
    }
    return gate.stable_hash(row)


def review_payload(subject, review_type, bh):
    return {
        "event_type": "review_attestation",
        "protocol_freeze_hash": gate.REGISTRATION_PROTOCOL_FREEZE,
        "subject_login": subject,
        "review_type": review_type,
        "evidence_bundle_hash": bh,
        "decision": "support",
        "attests_reviewed_evidence": True,
        "attests_no_conflict": True,
        "attests_distinct_human_to_best_knowledge": True,
        "attests_no_shared_control_for_evaluation": True,
        "reviewer_conflict_disclosure": "none",
    }


def valid_world(aff_a="independent", aff_b="independent"):
    reg_raw = [
        raw(1, "alice", reg_body("alice", "selector_labeler", aff_a), 3),
        raw(2, "bob", reg_body("bob", "reveal_auditor", aff_b), 3),
    ]
    reg_registry = registration.build_registry(proc.normalize_registration_comments(reg_raw))
    receipt_by_login = {r["github_login"]: r["receipt_hash"] for r in reg_registry["receipts"] if r["accepted"]}
    a = evidence_payload("alice", "selector_labeler", receipt_by_login["alice"], "abc")
    b = evidence_payload("bob", "reveal_auditor", receipt_by_login["bob"], "def")
    a_hash = bundle_hash(a, 10)
    b_hash = bundle_hash(b, 11)
    review_raw = [
        raw(10, "alice", fenced(a), 10),
        raw(11, "bob", fenced(b), 10),
        raw(12, "reviewer1", fenced(review_payload("alice", "identity", a_hash)), 10),
        raw(13, "reviewer2", fenced(review_payload("alice", "independence", a_hash)), 10),
        raw(14, "reviewer3", fenced(review_payload("bob", "identity", b_hash)), 10),
        raw(15, "reviewer4", fenced(review_payload("bob", "independence", b_hash)), 10),
    ]
    return reg_raw, review_raw


def rebuild(reg_raw, review_raw):
    return proc.rebuild_state(raw_registration_comments=reg_raw, raw_review_comments=review_raw)


def test_empty_world_remains_null():
    _, state = rebuild([], [])
    assert state["promoted_custodian_count"] == 0
    assert state["verified_registry"]["external_quorum_formed"] is False


def test_valid_world_yields_only_evidence_reviewed_quorum_candidate():
    _, state = rebuild(*valid_world())
    reg = state["verified_registry"]
    assert state["promoted_custodian_count"] == 2
    assert reg["external_quorum_formed"] is True
    assert reg["authority"] == "EVIDENCE_REVIEWED_TWO_ROLE_CUSTODIAN_QUORUM_CANDIDATE"
    assert reg["absolute_human_uniqueness_proven"] is False
    assert reg["absolute_independence_proven"] is False
    assert reg["external_success"] is False


def test_subject_cannot_self_review():
    reg_raw, review_raw = valid_world()
    review_raw[2]["user"]["login"] = "alice"
    _, state = rebuild(reg_raw, review_raw)
    assert state["verified_registry"]["external_quorum_formed"] is False
    assert any("REVIEWER_CONFLICT_FORBIDDEN" in r["problems"] for r in state["receipts"])


def test_custodian_candidate_cannot_review_other_candidate():
    reg_raw, review_raw = valid_world()
    review_raw[2]["user"]["login"] = "bob"
    _, state = rebuild(reg_raw, review_raw)
    assert state["verified_registry"]["external_quorum_formed"] is False
    assert any("CUSTODIAN_CANDIDATE_CANNOT_REVIEW" in r["problems"] for r in state["receipts"])


def test_project_owner_cannot_review():
    reg_raw, review_raw = valid_world()
    review_raw[2]["user"]["login"] = "leehyen0"
    _, state = rebuild(reg_raw, review_raw)
    assert state["verified_registry"]["external_quorum_formed"] is False
    assert any("REVIEWER_CONFLICT_FORBIDDEN" in r["problems"] for r in state["receipts"])


def test_exact_reviewer_set_coupling_blocks_quorum():
    reg_raw, review_raw = valid_world()
    review_raw[4]["user"]["login"] = "reviewer1"
    review_raw[5]["user"]["login"] = "reviewer2"
    _, state = rebuild(reg_raw, review_raw)
    reg = state["verified_registry"]
    assert reg["exact_reviewer_set_coupling"] is True
    assert reg["external_quorum_formed"] is False


def test_shared_named_affiliation_blocks_quorum():
    _, state = rebuild(*valid_world("Same Lab", "Same Lab"))
    reg = state["verified_registry"]
    assert reg["shared_affiliation_coupling"] is True
    assert reg["external_quorum_formed"] is False


def test_cross_role_evidence_reuse_blocks_quorum():
    reg_raw, review_raw = valid_world()
    b = json.loads(review_raw[1]["body"].split("\n",1)[1].rsplit("\n",1)[0])
    b["evidence"][0]["artifact_sha256"] = "a"*64
    review_raw[1]["body"] = fenced(b)
    _, state = rebuild(reg_raw, review_raw)
    assert state["verified_registry"]["external_quorum_formed"] is False
    assert state["verified_registry"]["reused_evidence_hashes"]


def test_non_github_identity_anchor_required():
    reg_raw, review_raw = valid_world()
    a = json.loads(review_raw[0]["body"].split("\n",1)[1].rsplit("\n",1)[0])
    a["evidence"] = [x for x in a["evidence"] if x["kind"] != "non_github_identity_anchor"]
    review_raw[0]["body"] = fenced(a)
    _, state = rebuild(reg_raw, review_raw)
    assert any("NON_GITHUB_IDENTITY_ANCHOR_REQUIRED" in r["problems"] for r in state["receipts"])


def test_sensitive_identity_material_is_rejected():
    reg_raw, review_raw = valid_world()
    a = json.loads(review_raw[0]["body"].split("\n",1)[1].rsplit("\n",1)[0])
    a["government_id"] = "forbidden"
    review_raw[0]["body"] = fenced(a)
    _, state = rebuild(reg_raw, review_raw)
    assert any("SENSITIVE_OR_PRIVATE_MATERIAL_FORBIDDEN" in r["problems"] for r in state["receipts"])


def test_wrong_registration_receipt_hash_rejected():
    reg_raw, review_raw = valid_world()
    a = json.loads(review_raw[0]["body"].split("\n",1)[1].rsplit("\n",1)[0])
    a["registration_receipt_hash"] = "f"*64
    review_raw[0]["body"] = fenced(a)
    _, state = rebuild(reg_raw, review_raw)
    assert any("REGISTRATION_RECEIPT_HASH_MISMATCH" in r["problems"] for r in state["receipts"])


def test_bot_review_receipts_not_reingested():
    bot = raw(90, "github-actions[bot]", "<!-- arte-identity-independence-review:10:abc -->\nreceipt", 10, user_type="Bot")
    assert proc.normalize_review_comments([bot]) == []


def test_wrong_issue_processor_event_rejected():
    event = {"issue": {"number": 8}, "comment": raw(91, "alice", "```json\n{}\n```", 8)}
    try:
        proc.process(event=event, raw_registration_comments=[], raw_review_comments=[])
    except ValueError as exc:
        assert str(exc) == "WRONG_EVIDENCE_REVIEW_ISSUE"
    else:
        raise AssertionError("wrong issue accepted")


def test_target_comment_appended_when_fetch_snapshot_lags():
    comment = raw(92, "alice", "```json\n{}\n```", 10)
    receipt, _, state, _ = proc.process(event={"issue": {"number": 10}, "comment": comment}, raw_registration_comments=[], raw_review_comments=[])
    assert receipt["source_comment_id"] == 92
    assert receipt["accepted"] is False
    assert state["verified_registry"]["external_quorum_formed"] is False
