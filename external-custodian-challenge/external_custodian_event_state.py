from __future__ import annotations
from copy import deepcopy
from hashlib import sha256
from typing import Any, Mapping, Sequence
import json, re

REGISTRATION_ISSUE_NUMBER = 3
EVENT_LEDGER_ISSUE_NUMBER = 8
EVENT_PROTOCOL_FREEZE = "c6f5e17e8e77358c01ee87d3196659fdda44415b32ccd140190d1fc3c09dfdf2"
QUORUM_PROTOCOL_FREEZE = "540f9b1087643580d21a162174a956e8a15d2ad2de2cc6c64b8bb02b612a0444"
EVENT_TYPES = (
    "selector_challenge_commit",
    "auditor_reveal_hash_commit",
    "prediction_seal",
    "selector_reveal",
    "auditor_reveal_confirmation",
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): canonical(value[k]) for k in sorted(value, key=lambda x: str(x))}
    if isinstance(value, (list, tuple)):
        return [canonical(x) for x in value]
    return value


def stable_hash(value: Any) -> str:
    return sha256(json.dumps(canonical(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def empty_verified_registry() -> dict[str, Any]:
    row = {
        "schema": "arte.external_custodian_verified_registry/v1",
        "registration_issue": REGISTRATION_ISSUE_NUMBER,
        "verified_custodians": [],
        "identity_review_complete": False,
        "independence_review_complete": False,
        "external_quorum_formed": False,
        "authority": "NULL_NO_VERIFIED_EXTERNAL_CUSTODIANS",
        "promotion": False,
        "agi": False,
        "asi": False,
    }
    row["registry_hash"] = stable_hash(row)
    return row


def validate_verified_registry(registry: Mapping[str, Any]) -> list[str]:
    problems: list[str] = []
    raw = deepcopy(dict(registry))
    supplied = raw.pop("registry_hash", None)
    if supplied != stable_hash(raw):
        problems.append("REGISTRY_HASH_MISMATCH")
    rows = list(registry.get("verified_custodians", []))
    logins = [str(x.get("github_login", "")) for x in rows]
    if len(logins) != len(set(logins)):
        problems.append("DUPLICATE_VERIFIED_LOGIN")
    roles: dict[str, list[str]] = {}
    for row in rows:
        login = str(row.get("github_login", ""))
        role = str(row.get("role", ""))
        if role not in {"selector_labeler", "reveal_auditor"}:
            problems.append("UNSUPPORTED_VERIFIED_ROLE")
        if row.get("identity_verified") is not True:
            problems.append(f"IDENTITY_NOT_VERIFIED:{login}")
        if row.get("independence_verified") is not True:
            problems.append(f"INDEPENDENCE_NOT_VERIFIED:{login}")
        roles.setdefault(role, []).append(login)
    expected = (
        len(roles.get("selector_labeler", [])) >= 1
        and len(roles.get("reveal_auditor", [])) >= 1
        and len(set(roles.get("selector_labeler", []) + roles.get("reveal_auditor", []))) >= 2
        and registry.get("identity_review_complete") is True
        and registry.get("independence_review_complete") is True
    )
    if bool(registry.get("external_quorum_formed")) != expected:
        problems.append("QUORUM_FLAG_MISMATCH")
    return problems


def extract_single_json_block(body: str) -> tuple[dict[str, Any] | None, list[str]]:
    text = str(body or "").strip()
    blocks = re.findall(r"```(?:json)?\s*(.*?)```", text, flags=re.I | re.S)
    if len(blocks) != 1:
        return None, ["EXACTLY_ONE_FENCED_JSON_REQUIRED"]
    if re.fullmatch(r"```(?:json)?\s*(.*?)```", text, flags=re.I | re.S) is None:
        return None, ["SURROUNDING_PROSE_FORBIDDEN"]
    try:
        value = json.loads(blocks[0])
    except json.JSONDecodeError:
        return None, ["INVALID_JSON"]
    if not isinstance(value, dict):
        return None, ["JSON_OBJECT_REQUIRED"]
    return value, []


def _verified_role(registry: Mapping[str, Any], login: str) -> str | None:
    for row in registry.get("verified_custodians", []):
        if row.get("github_login") == login:
            return str(row.get("role"))
    return None


def validate_event_claim(*, author_login: str, author_type: str, payload: Mapping[str, Any], registry: Mapping[str, Any], predictor_login: str) -> list[str]:
    problems: list[str] = []
    event_type = str(payload.get("event_type", ""))
    if event_type not in EVENT_TYPES:
        return ["UNSUPPORTED_EVENT_TYPE"]
    if payload.get("protocol_freeze_hash") != EVENT_PROTOCOL_FREEZE:
        problems.append("EVENT_PROTOCOL_FREEZE_MISMATCH")
    if payload.get("quorum_protocol_freeze_hash") != QUORUM_PROTOCOL_FREEZE:
        problems.append("QUORUM_PROTOCOL_FREEZE_MISMATCH")
    if str(author_type).lower() == "bot" or str(author_login).endswith("[bot]"):
        problems.append("BOT_EVENT_FORBIDDEN")
    role = _verified_role(registry, author_login)
    if event_type in {"selector_challenge_commit", "selector_reveal"} and role != "selector_labeler":
        problems.append("SELECTOR_ROLE_REQUIRED")
    if event_type in {"auditor_reveal_hash_commit", "auditor_reveal_confirmation"} and role != "reveal_auditor":
        problems.append("AUDITOR_ROLE_REQUIRED")
    if event_type == "prediction_seal" and author_login != predictor_login:
        problems.append("PREDICTOR_LOGIN_REQUIRED")
    required = {
        "selector_challenge_commit": ("challenge_hash", "selector_reveal_hash"),
        "auditor_reveal_hash_commit": ("challenge_hash", "selector_reveal_hash", "auditor_commitment_hash"),
        "prediction_seal": ("challenge_hash", "prediction_seal_hash"),
        "selector_reveal": ("challenge_hash", "selector_reveal_hash", "reveal_hash"),
        "auditor_reveal_confirmation": ("challenge_hash", "selector_reveal_hash", "auditor_commitment_hash"),
    }[event_type]
    for field in required:
        if not HEX64.fullmatch(str(payload.get(field, ""))):
            problems.append(f"INVALID_HASH:{field}")
    forbidden = {"secret", "nonce", "private_reveal", "private_tasks", "expected_labels", "typed_transformations", "witnesses", "answer", "label"}
    if forbidden.intersection(map(str, payload)):
        problems.append("PRIVATE_MATERIAL_FORBIDDEN")
    allowed = {"event_type", "protocol_freeze_hash", "quorum_protocol_freeze_hash", "challenge_hash", "selector_reveal_hash", "auditor_commitment_hash", "prediction_seal_hash", "reveal_hash", "submitted_at"}
    extras = sorted(set(map(str, payload)) - allowed)
    if extras:
        problems.append("UNEXPECTED_FIELDS:" + ",".join(extras))
    return problems


def build_state(*, registry: Mapping[str, Any], comments: Sequence[Mapping[str, Any]], predictor_login: str) -> dict[str, Any]:
    registry_problems = validate_verified_registry(registry)
    quorum_ready = not registry_problems and registry.get("external_quorum_formed") is True
    accepted: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    seen: set[str] = set()
    challenge_hash = selector_reveal_hash = auditor_commitment_hash = prediction_seal_hash = reveal_hash = None

    def reject(comment: Mapping[str, Any], problems: list[str]) -> None:
        receipt = {"source_comment_id": int(comment.get("id", 0)), "author_login": str(comment.get("author_login", "")), "accepted": False, "disposition": "REJECTED_EVENT", "problems": list(problems)}
        receipt["receipt_hash"] = stable_hash(receipt)
        receipts.append(receipt)

    if not quorum_ready:
        for comment in comments:
            reject(comment, ["VERIFIED_EXTERNAL_QUORUM_REQUIRED"])
        phase = "WAITING_FOR_VERIFIED_EXTERNAL_QUORUM"
    else:
        phase = "WAITING_FOR_SELECTOR_CHALLENGE_COMMIT"
        ordered = sorted(comments, key=lambda x: (str(x.get("created_at", "")), int(x.get("id", 0))))
        for comment in ordered:
            payload, parse_problems = extract_single_json_block(str(comment.get("body", "")))
            problems = list(parse_problems)
            if payload is not None:
                problems.extend(validate_event_claim(author_login=str(comment.get("author_login", "")), author_type=str(comment.get("author_type", "")), payload=payload, registry=registry, predictor_login=predictor_login))
            event_type = str(payload.get("event_type", "")) if payload else ""
            if not problems and event_type in seen:
                problems.append("DUPLICATE_EVENT_TYPE")
            if not problems:
                if event_type == "selector_challenge_commit":
                    if phase != "WAITING_FOR_SELECTOR_CHALLENGE_COMMIT":
                        problems.append("EVENT_OUT_OF_ORDER")
                    else:
                        challenge_hash = payload["challenge_hash"]
                        selector_reveal_hash = payload["selector_reveal_hash"]
                        phase = "WAITING_FOR_AUDITOR_REVEAL_HASH_COMMIT"
                elif event_type == "auditor_reveal_hash_commit":
                    if phase != "WAITING_FOR_AUDITOR_REVEAL_HASH_COMMIT":
                        problems.append("EVENT_OUT_OF_ORDER")
                    elif payload["challenge_hash"] != challenge_hash or payload["selector_reveal_hash"] != selector_reveal_hash:
                        problems.append("COMMIT_REFERENCE_MISMATCH")
                    else:
                        auditor_commitment_hash = payload["auditor_commitment_hash"]
                        phase = "WAITING_FOR_PREDICTION_SEAL"
                elif event_type == "prediction_seal":
                    if phase != "WAITING_FOR_PREDICTION_SEAL":
                        problems.append("EVENT_OUT_OF_ORDER")
                    elif payload["challenge_hash"] != challenge_hash:
                        problems.append("PREDICTION_REFERENCE_MISMATCH")
                    else:
                        prediction_seal_hash = payload["prediction_seal_hash"]
                        phase = "WAITING_FOR_SELECTOR_REVEAL"
                elif event_type == "selector_reveal":
                    if phase != "WAITING_FOR_SELECTOR_REVEAL":
                        problems.append("EVENT_OUT_OF_ORDER")
                    elif payload["challenge_hash"] != challenge_hash or payload["selector_reveal_hash"] != selector_reveal_hash:
                        problems.append("REVEAL_REFERENCE_MISMATCH")
                    else:
                        reveal_hash = payload["reveal_hash"]
                        phase = "WAITING_FOR_AUDITOR_REVEAL_CONFIRMATION"
                elif event_type == "auditor_reveal_confirmation":
                    if phase != "WAITING_FOR_AUDITOR_REVEAL_CONFIRMATION":
                        problems.append("EVENT_OUT_OF_ORDER")
                    elif payload["challenge_hash"] != challenge_hash or payload["selector_reveal_hash"] != selector_reveal_hash or payload["auditor_commitment_hash"] != auditor_commitment_hash:
                        problems.append("AUDITOR_CONFIRMATION_REFERENCE_MISMATCH")
                    else:
                        phase = "COMMIT_REVEAL_SEQUENCE_COMPLETE_CANDIDATE"
            if problems:
                reject(comment, problems)
                continue
            seen.add(event_type)
            row = {"source_comment_id": int(comment.get("id", 0)), "author_login": str(comment.get("author_login", "")), "event_type": event_type, "payload_hash": stable_hash(payload)}
            row["event_hash"] = stable_hash(row)
            accepted.append(row)
            receipt = {"source_comment_id": row["source_comment_id"], "author_login": row["author_login"], "accepted": True, "disposition": "ACCEPTED_SEQUENCE_EVENT_IDENTITY_BOUND", "event_type": event_type, "event_hash": row["event_hash"], "problems": []}
            receipt["receipt_hash"] = stable_hash(receipt)
            receipts.append(receipt)

    state = {"schema": "arte.external_custodian_commit_reveal_state/v1", "registry_hash": registry.get("registry_hash"), "registry_valid": not registry_problems, "verified_external_quorum": quorum_ready, "phase": phase, "accepted_event_count": len(accepted), "accepted_events": accepted, "receipts": receipts, "challenge_hash": challenge_hash, "selector_reveal_hash": selector_reveal_hash, "auditor_commitment_hash": auditor_commitment_hash, "prediction_seal_hash": prediction_seal_hash, "reveal_hash": reveal_hash, "sequence_complete_candidate": phase == "COMMIT_REVEAL_SEQUENCE_COMPLETE_CANDIDATE", "independent_evaluation_complete": False, "external_success": False, "patch_authority": False, "promotion": False, "agi": False, "asi": False, "registry_problems": registry_problems}
    state["state_hash"] = stable_hash(state)
    return state
