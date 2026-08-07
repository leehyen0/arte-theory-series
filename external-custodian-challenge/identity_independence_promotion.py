from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import Any, Mapping, Sequence
import json
import re

REGISTRATION_ISSUE_NUMBER = 3
EVIDENCE_REVIEW_ISSUE_NUMBER = 10
REGISTRATION_PROTOCOL_FREEZE = "540f9b1087643580d21a162174a956e8a15d2ad2de2cc6c64b8bb02b612a0444"
OWNER_LOGIN = "leehyen0"

ROLES = {"selector_labeler", "reveal_auditor"}
REVIEW_TYPES = {"identity", "independence"}
EVIDENCE_KINDS = {
    "github_account_control",
    "non_github_identity_anchor",
    "evaluation_independence",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def canonical(v: Any) -> Any:
    if isinstance(v, Mapping):
        return {str(k): canonical(v[k]) for k in sorted(v, key=lambda x: str(x))}
    if isinstance(v, (list, tuple)):
        return [canonical(x) for x in v]
    return v


def stable_hash(v: Any) -> str:
    return sha256(json.dumps(canonical(v), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


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


def accepted_registration_map(registration_receipts: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in registration_receipts:
        if row.get("accepted") is not True:
            continue
        claim = row.get("claim") if isinstance(row.get("claim"), Mapping) else {}
        login = str(claim.get("github_login") or row.get("github_login") or row.get("subject_login") or row.get("author_login") or "")
        role = str(claim.get("role") or row.get("role") or "")
        if login and role in ROLES:
            out.setdefault(login, {
                "github_login": login,
                "role": role,
                "registration_receipt_hash": str(row.get("receipt_hash", "")),
                "registration_hash": str(claim.get("registration_hash", "")),
                "affiliation": str(claim.get("affiliation") or row.get("affiliation") or ""),
                "conflict_disclosure": str(claim.get("conflict_disclosure") or row.get("conflict_disclosure") or ""),
            })
    return out


def validate_evidence_bundle(*, author_login: str, author_type: str, payload: Mapping[str, Any], registrations: Mapping[str, Mapping[str, Any]]) -> list[str]:
    p: list[str] = []
    subject = str(payload.get("subject_login", ""))
    role = str(payload.get("subject_role", ""))
    registration = registrations.get(subject)
    if registration is None:
        p.append("ACCEPTED_REGISTRATION_REQUIRED")
    else:
        if role != registration.get("role"):
            p.append("REGISTRATION_ROLE_MISMATCH")
        if payload.get("registration_receipt_hash") != registration.get("registration_receipt_hash"):
            p.append("REGISTRATION_RECEIPT_HASH_MISMATCH")
    if author_login != subject:
        p.append("SUBJECT_MUST_POST_OWN_EVIDENCE_BUNDLE")
    if subject == OWNER_LOGIN:
        p.append("OWNER_CANNOT_BE_CUSTODIAN")
    if str(author_type).lower() == "bot" or author_login.endswith("[bot]"):
        p.append("BOT_EVIDENCE_FORBIDDEN")
    if role not in ROLES:
        p.append("UNSUPPORTED_ROLE")
    if payload.get("protocol_freeze_hash") != REGISTRATION_PROTOCOL_FREEZE:
        p.append("PROTOCOL_FREEZE_MISMATCH")

    evidence = list(payload.get("evidence", []))
    kinds = [str(x.get("kind", "")) for x in evidence if isinstance(x, Mapping)]
    for required in EVIDENCE_KINDS:
        if required not in kinds:
            p.append({
                "github_account_control": "GITHUB_ACCOUNT_CONTROL_EVIDENCE_REQUIRED",
                "non_github_identity_anchor": "NON_GITHUB_IDENTITY_ANCHOR_REQUIRED",
                "evaluation_independence": "EVALUATION_INDEPENDENCE_EVIDENCE_REQUIRED",
            }[required])
    hashes = []
    for idx, item in enumerate(evidence):
        if not isinstance(item, Mapping):
            p.append(f"INVALID_EVIDENCE_ROW:{idx}")
            continue
        kind = str(item.get("kind", ""))
        if kind not in EVIDENCE_KINDS:
            p.append(f"UNSUPPORTED_EVIDENCE_KIND:{kind}")
        digest = str(item.get("artifact_sha256", ""))
        if not HEX64.fullmatch(digest):
            p.append(f"INVALID_EVIDENCE_HASH:{idx}")
        else:
            hashes.append(digest)
        if kind != "evaluation_independence" and not str(item.get("public_locator", "")):
            p.append(f"PUBLIC_LOCATOR_REQUIRED:{idx}")
    if len(hashes) != len(set(hashes)):
        p.append("DUPLICATE_EVIDENCE_HASH_WITHIN_BUNDLE")

    forbidden = {"government_id", "home_address", "phone", "private_email", "secret", "nonce", "private_reveal", "expected_labels", "witnesses", "typed_transformations"}
    if forbidden.intersection(map(str, payload)):
        p.append("SENSITIVE_OR_PRIVATE_MATERIAL_FORBIDDEN")
    allowed = {"event_type", "protocol_freeze_hash", "subject_login", "subject_role", "registration_receipt_hash", "conflict_disclosure", "evidence", "submitted_at"}
    extras = sorted(set(map(str, payload)) - allowed)
    if extras:
        p.append("UNEXPECTED_FIELDS:" + ",".join(extras))
    return p


def validate_review_attestation(*, author_login: str, author_type: str, payload: Mapping[str, Any], registrations: Mapping[str, Mapping[str, Any]], evidence_bundles: Mapping[str, Mapping[str, Any]]) -> list[str]:
    p: list[str] = []
    subject = str(payload.get("subject_login", ""))
    review_type = str(payload.get("review_type", ""))
    if review_type not in REVIEW_TYPES:
        p.append("UNSUPPORTED_REVIEW_TYPE")
    if author_login in {subject, OWNER_LOGIN}:
        p.append("REVIEWER_CONFLICT_FORBIDDEN")
    if author_login in registrations:
        p.append("CUSTODIAN_CANDIDATE_CANNOT_REVIEW")
    if str(author_type).lower() == "bot" or author_login.endswith("[bot]"):
        p.append("BOT_REVIEW_FORBIDDEN")
    bundle = evidence_bundles.get(subject)
    if bundle is None:
        p.append("SUBJECT_EVIDENCE_BUNDLE_REQUIRED")
    elif payload.get("evidence_bundle_hash") != bundle.get("bundle_hash"):
        p.append("EVIDENCE_BUNDLE_HASH_MISMATCH")
    if payload.get("decision") != "support":
        p.append("SUPPORT_DECISION_REQUIRED")
    if payload.get("attests_reviewed_evidence") is not True:
        p.append("REVIEW_EVIDENCE_ATTESTATION_REQUIRED")
    if payload.get("attests_no_conflict") is not True:
        p.append("REVIEWER_NO_CONFLICT_ATTESTATION_REQUIRED")
    if payload.get("attests_distinct_human_to_best_knowledge") is not True:
        p.append("DISTINCT_HUMAN_ATTESTATION_REQUIRED")
    if review_type == "independence" and payload.get("attests_no_shared_control_for_evaluation") is not True:
        p.append("NO_SHARED_CONTROL_ATTESTATION_REQUIRED")
    if payload.get("protocol_freeze_hash") != REGISTRATION_PROTOCOL_FREEZE:
        p.append("PROTOCOL_FREEZE_MISMATCH")
    if {"secret", "nonce", "private_reveal", "government_id", "home_address", "private_contact"}.intersection(map(str, payload)):
        p.append("PRIVATE_REVIEW_MATERIAL_FORBIDDEN")
    allowed = {"event_type", "protocol_freeze_hash", "subject_login", "review_type", "evidence_bundle_hash", "decision", "attests_reviewed_evidence", "attests_no_conflict", "attests_distinct_human_to_best_knowledge", "attests_no_shared_control_for_evaluation", "reviewer_conflict_disclosure", "submitted_at"}
    extras = sorted(set(map(str, payload)) - allowed)
    if extras:
        p.append("UNEXPECTED_FIELDS:" + ",".join(extras))
    return p


def build_promotion_state(*, registration_receipts: Sequence[Mapping[str, Any]], comments: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    registrations = accepted_registration_map(registration_receipts)
    receipts: list[dict[str, Any]] = []
    bundles: dict[str, dict[str, Any]] = {}
    reviews: list[dict[str, Any]] = []

    for comment in sorted(comments, key=lambda x: (str(x.get("created_at", "")), int(x.get("id", 0)))):
        payload, problems = extract_single_json_block(str(comment.get("body", "")))
        author = str(comment.get("author_login", ""))
        author_type = str(comment.get("author_type", ""))
        if payload is not None:
            event_type = str(payload.get("event_type", ""))
            if event_type == "evidence_bundle":
                problems.extend(validate_evidence_bundle(author_login=author, author_type=author_type, payload=payload, registrations=registrations))
                subject = str(payload.get("subject_login", ""))
                if not problems and subject in bundles:
                    problems.append("DUPLICATE_SUBJECT_EVIDENCE_BUNDLE")
                if not problems:
                    bundle = {"subject_login": subject, "subject_role": str(payload["subject_role"]), "registration_receipt_hash": str(payload["registration_receipt_hash"]), "conflict_disclosure": str(payload.get("conflict_disclosure", "")), "evidence": canonical(payload.get("evidence", [])), "source_comment_id": int(comment.get("id", 0))}
                    bundle["bundle_hash"] = stable_hash(bundle)
                    bundles[subject] = bundle
            elif event_type == "review_attestation":
                problems.extend(validate_review_attestation(author_login=author, author_type=author_type, payload=payload, registrations=registrations, evidence_bundles=bundles))
                if not problems:
                    row = {"reviewer_login": author, "subject_login": str(payload["subject_login"]), "review_type": str(payload["review_type"]), "evidence_bundle_hash": str(payload["evidence_bundle_hash"]), "source_comment_id": int(comment.get("id", 0))}
                    row["review_hash"] = stable_hash(row)
                    if any(r["reviewer_login"] == row["reviewer_login"] and r["subject_login"] == row["subject_login"] and r["review_type"] == row["review_type"] for r in reviews):
                        problems.append("DUPLICATE_REVIEW_ATTESTATION")
                    else:
                        reviews.append(row)
            else:
                problems.append("UNSUPPORTED_EVENT_TYPE")
        receipt = {"source_comment_id": int(comment.get("id", 0)), "author_login": author, "accepted": not problems, "disposition": "ACCEPTED_REVIEW_LEDGER_EVENT" if not problems else "REJECTED_REVIEW_LEDGER_EVENT", "problems": list(problems)}
        receipt["receipt_hash"] = stable_hash(receipt)
        receipts.append(receipt)

    hash_subjects: dict[str, set[str]] = {}
    for subject, bundle in bundles.items():
        for item in bundle["evidence"]:
            digest = str(item.get("artifact_sha256", ""))
            if digest:
                hash_subjects.setdefault(digest, set()).add(subject)
    reused_hashes = sorted(h for h, subjects in hash_subjects.items() if len(subjects) > 1)

    promoted = []
    for login, reg in registrations.items():
        bundle = bundles.get(login)
        if bundle is None:
            continue
        identity_reviewers = sorted({r["reviewer_login"] for r in reviews if r["subject_login"] == login and r["review_type"] == "identity"})
        independence_reviewers = sorted({r["reviewer_login"] for r in reviews if r["subject_login"] == login and r["review_type"] == "independence"})
        subject_hashes = {str(x.get("artifact_sha256", "")) for x in bundle["evidence"]}
        if identity_reviewers and independence_reviewers and set(identity_reviewers).isdisjoint(independence_reviewers) and not subject_hashes.intersection(reused_hashes):
            row = {"github_login": login, "role": reg["role"], "registration_receipt_hash": reg["registration_receipt_hash"], "evidence_bundle_hash": bundle["bundle_hash"], "identity_reviewers": identity_reviewers, "independence_reviewers": independence_reviewers, "identity_evidence_reviewed": True, "independence_evidence_reviewed": True, "identity_verified": True, "independence_verified": True, "absolute_human_uniqueness_proven": False, "absolute_independence_proven": False}
            row["promotion_record_hash"] = stable_hash(row)
            promoted.append(row)

    roles = {r["role"]: r for r in promoted}
    two_roles = set(roles) == ROLES and len({r["github_login"] for r in promoted}) == 2
    evidence_hashes = [r["evidence_bundle_hash"] for r in promoted]
    evidence_distinct = len(evidence_hashes) == len(set(evidence_hashes))
    exact_reviewer_set_coupling = False
    shared_affiliation_coupling = False
    if len(promoted) == 2:
        a, b = promoted
        exact_reviewer_set_coupling = a["identity_reviewers"] == b["identity_reviewers"] and a["independence_reviewers"] == b["independence_reviewers"]
        aff_a = str(registrations.get(a["github_login"], {}).get("affiliation", "")).strip().lower()
        aff_b = str(registrations.get(b["github_login"], {}).get("affiliation", "")).strip().lower()
        shared_affiliation_coupling = bool(aff_a == aff_b and aff_a not in {"", "independent", "undisclosed", "none"})

    quorum = two_roles and evidence_distinct and not reused_hashes and not exact_reviewer_set_coupling and not shared_affiliation_coupling
    registry = {"schema": "arte.external_custodian_verified_registry/v2", "registration_issue": REGISTRATION_ISSUE_NUMBER, "evidence_review_issue": EVIDENCE_REVIEW_ISSUE_NUMBER, "verified_custodians": promoted, "identity_review_complete": quorum, "independence_review_complete": quorum, "external_quorum_formed": quorum, "authority": "EVIDENCE_REVIEWED_TWO_ROLE_CUSTODIAN_QUORUM_CANDIDATE" if quorum else "NULL_NO_EVIDENCE_REVIEWED_EXTERNAL_QUORUM", "reused_evidence_hashes": reused_hashes, "exact_reviewer_set_coupling": exact_reviewer_set_coupling, "shared_affiliation_coupling": shared_affiliation_coupling, "absolute_human_uniqueness_proven": False, "absolute_independence_proven": False, "independent_evaluation_complete": False, "external_success": False, "patch_authority": False, "promotion": False, "agi": False, "asi": False}
    registry["registry_hash"] = stable_hash(registry)
    state = {"schema": "arte.external_custodian_identity_independence_promotion_state/v1", "accepted_registration_count": len(registrations), "evidence_bundle_count": len(bundles), "accepted_review_count": len(reviews), "promoted_custodian_count": len(promoted), "receipts": receipts, "verified_registry": registry, "claim_boundary": {"protocol_level_evidence_review": True, "legal_identity_verified": False, "absolute_human_uniqueness_proven": False, "absolute_independence_proven": False, "independent_evaluation_complete": False, "external_success": False, "promotion": False, "agi": False, "asi": False}}
    state["state_hash"] = stable_hash(state)
    return state
