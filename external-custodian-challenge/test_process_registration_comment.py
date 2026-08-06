import json
from pathlib import Path
import subprocess
import sys

import process_registration_comment as P
import public_registration_intake as I


def payload(login, role):
    return {
        "github_login": login,
        "role": role,
        "affiliation": "independent",
        "conflict_disclosure": "none",
        "public_key_fingerprint": "",
        "protocol_freeze_hash": I.PROTOCOL_FREEZE_HASH,
        "attests_no_predictor_access": True,
    }


def raw(comment_id, login, role):
    return {
        "id": comment_id,
        "body": "```json\n" + json.dumps(payload(login, role)) + "\n```",
        "user": {"login": login, "type": "User"},
        "html_url": f"https://example.test/{comment_id}",
        "created_at": "2026-08-06T00:00:00Z",
    }


def event(comment):
    return {
        "action": "created",
        "issue": {"number": 3},
        "comment": comment,
    }


def test_processor_accepts_target_and_builds_fail_closed_registry():
    alice = raw(1, "alice", "selector_labeler")
    bob = raw(2, "bob", "reveal_auditor")
    receipt, registry, markdown = P.process(
        event=event(bob),
        raw_comments=[alice, bob],
    )
    assert receipt["accepted"] is True
    assert registry["syntactic_two_role_candidate"] is True
    assert registry["external_quorum_formed"] is False
    assert "ACCEPTED_CLAIM_IDENTITY_UNVERIFIED" in markdown


def test_cli_dry_run_writes_receipt_registry_and_response(tmp_path):
    comment = raw(7, "carol", "selector_labeler")
    event_path = tmp_path / "event.json"
    comments_path = tmp_path / "comments.json"
    output_dir = tmp_path / "out"
    event_path.write_text(json.dumps(event(comment)))
    comments_path.write_text(json.dumps([comment]))

    result = subprocess.run(
        [
            sys.executable,
            str(Path(P.__file__)),
            "--event", str(event_path),
            "--comments-json", str(comments_path),
            "--output-dir", str(output_dir),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    output = json.loads(result.stdout)
    assert output["accepted"] is True
    assert output["response_posted"] is False
    assert (output_dir / "registration_receipt.json").exists()
    assert (output_dir / "registration_registry.json").exists()
    assert "arte-registration-intake:7:" in (
        output_dir / "registration_response.md"
    ).read_text()
