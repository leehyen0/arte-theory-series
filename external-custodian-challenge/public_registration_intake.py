from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import Any, Iterable, Mapping
import json
import re

PROTOCOL_FREEZE_HASH = "540f9b1087643580d21a162174a956e8a15d2ad2de2cc6c64b8bb02b612a0444"
REGISTRATION_ISSUE_NUMBER = 3
OWNER_LOGIN = "leehyen0"
ALLOWED_ROLES = frozenset({"selector_labeler", "reveal_auditor"})
EXPECTED_FIELDS = frozenset({
    "github_login",
    "role",
    "affiliation",
    "conflict_disclosure",
    "public_key_fingerprint",
    "protocol_freeze_hash",
    "attests_no_predictor_access",
})
PRIVATE_KEYS = frozenset({
    "secret", "secrets", "nonce", "nonces", "reveal", "private_reveal",
    "label", "labels", "answer", "answers", "expected_label",
    "expected_labels", "expected_commitment", "expected_commitments",
    "transformation", "transformations", "typed_transformation",
    "typed_transformations", "witness", "witnesses", "witness_ledger",
    "witness_ledgers", "private_task", "private_tasks", "selector_secret",
    "auditor_secret", "hmac_secret",
})
_FENCED_JSON = re.compile(
    r"\A\s*```(?:json)?[ \t]*\r?\n(?P<payload>.*?)\r?\n```\s*\Z",
    re.IGNORECASE | re.DOTALL,
)


def canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): canonical(value[k]) for k in sorted(value, key=lambda x: str(x))}
    if isinstance(value, (list, tuple)):
        return [canonical(x) for x in value]
    if isinstance(value, set):
        return [canonical(x) for x in sorted(value, key=repr)]
    return value


def stable_hash(value: Any) -> str:
    payload = json.dumps(
        canonical(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return sha256(payload).hexdigest()


def private_paths(value: Any, path: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            if key_text.lower() in PRIVATE_KEYS:
                found.append(f"{path}.{key_text}")
            found.extend(private_paths(child, f"{path}.{key_text}"))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            found.extend(private_paths(child, f"{path}[{index}]"))
    return found


def parse_registration_comment(body: str) -> tuple[dict[str, Any] | None, list[str]]:
    problems: list[str] = []
    body_text = str(body or "")
    if body_text.count("```") != 2:
        return None, ["EXACTLY_ONE_FENCED_JSON_BLOCK_REQUIRED"]
    match = _FENCED_JSON.fullmatch(body_text)
    if not match:
        return None, ["EXACTLY_ONE_FENCED_JSON_BLOCK_REQUIRED"]

    try:
        parsed = json.loads(match.group("payload"))
    except json.JSONDecodeError:
        return None, ["INVALID_JSON"]

    if not isinstance(parsed, dict):
        return None, ["JSON_OBJECT_REQUIRED"]

    private = private_paths(parsed)
    if private:
        problems.append("PRIVATE_MATERIAL_FORBIDDEN:" + ",".join(private))

    fields = frozenset(map(str, parsed))
    missing = sorted(EXPECTED_FIELDS - fields)
    extra = sorted(fields - EXPECTED_FIELDS)
    if missing:
        problems.append("MISSING_FIELDS:" + ",".join(missing))
    if extra:
        problems.append("UNEXPECTED_FIELDS:" + ",".join(extra))

    return dict(parsed), problems


def validate_claim(
    *,
    body: str,
    author_login: str,
    author_type: str,
    comment_id: int,
    comment_url: str,
    created_at: str,
    issue_number: int = REGISTRATION_ISSUE_NUMBER,
) -> dict[str, Any]:
    parsed, problems = parse_registration_comment(body)
    author = str(author_login or "").strip()
    author_lower = author.lower()

    if issue_number != REGISTRATION_ISSUE_NUMBER:
        problems.append("WRONG_REGISTRATION_ISSUE")
    if not author:
        problems.append("AUTHOR_LOGIN_MISSING")
    if str(author_type or "").lower() == "bot" or author_lower.endswith("[bot]"):
        problems.append("BOT_REGISTRATION_FORBIDDEN")
    if author_lower == OWNER_LOGIN.lower():
        problems.append("OWNER_SELF_CUSTODY_FORBIDDEN")

    if parsed is not None:
        claimed_login = str(parsed.get("github_login", "")).strip()
        if claimed_login.lower() != author_lower:
            problems.append("COMMENT_AUTHOR_LOGIN_MISMATCH")
        if parsed.get("role") not in ALLOWED_ROLES:
            problems.append("UNSUPPORTED_ROLE")
        if parsed.get("protocol_freeze_hash") != PROTOCOL_FREEZE_HASH:
            problems.append("PROTOCOL_FREEZE_HASH_MISMATCH")
        if parsed.get("attests_no_predictor_access") is not True:
            problems.append("PREDICTOR_ACCESS_ATTESTATION_REQUIRED")
        for field in ("github_login", "role", "affiliation", "conflict_disclosure"):
            if not isinstance(parsed.get(field), str) or not parsed[field].strip():
                problems.append(f"NONEMPTY_STRING_REQUIRED:{field}")
        if not isinstance(parsed.get("public_key_fingerprint"), str):
            problems.append("STRING_REQUIRED:public_key_fingerprint")

    accepted = not problems and parsed is not None
    claim: dict[str, Any] | None = None
    if accepted:
        claim = canonical({
            "schema": "arte.external_custodian_registration_claim/v1",
            "custodian_id": f"github:{author_lower}:comment:{int(comment_id)}",
            "github_login": author,
            "role": parsed["role"],
            "affiliation": parsed["affiliation"],
            "conflict_disclosure": parsed["conflict_disclosure"],
            "public_key_fingerprint": parsed["public_key_fingerprint"],
            "protocol_freeze_hash": parsed["protocol_freeze_hash"],
            "attests_no_predictor_access": True,
            "source_issue_number": int(issue_number),
            "source_comment_id": int(comment_id),
            "source_comment_url": str(comment_url),
            "registered_at": str(created_at),
            "identity_verified": False,
            "affiliation_verified": False,
            "independence_verified": False,
            "predictor_access_independently_verified": False,
            "authority": "ACCEPTED_CLAIM_IDENTITY_UNVERIFIED",
            "external_success_credit": 0,
            "promotion": False,
            "agi": False,
            "asi": False,
        })
        claim["registration_hash"] = stable_hash(claim)

    receipt = canonical({
        "schema": "arte.external_custodian_registration_intake_receipt/v1",
        "source_issue_number": int(issue_number),
        "source_comment_id": int(comment_id),
        "github_login": author,
        "accepted": accepted,
        "disposition": (
            "ACCEPTED_CLAIM_IDENTITY_UNVERIFIED"
            if accepted
            else "REJECTED_REGISTRATION_CLAIM"
        ),
        "problems": sorted(set(problems)),
        "claim": claim,
        "claim_boundary": {
            "identity_verified": False,
            "affiliation_verified": False,
            "independence_verified": False,
            "external_quorum_formed": False,
            "independent_evaluation": False,
            "external_success_credit": 0,
            "external_authority": False,
            "promotion": False,
            "agi": False,
            "asi": False,
        },
    })
    receipt["receipt_hash"] = stable_hash(receipt)
    return receipt


def build_registry(comment_records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    ordered = sorted(comment_records, key=lambda row: int(row.get("id", 0)))
    accepted_by_login: dict[str, dict[str, Any]] = {}
    receipts: list[dict[str, Any]] = []

    for row in ordered:
        receipt = validate_claim(
            body=str(row.get("body", "")),
            author_login=str(row.get("author_login", "")),
            author_type=str(row.get("author_type", "")),
            comment_id=int(row.get("id", 0)),
            comment_url=str(row.get("html_url", "")),
            created_at=str(row.get("created_at", "")),
            issue_number=int(row.get("issue_number", REGISTRATION_ISSUE_NUMBER)),
        )
        login = str(receipt.get("github_login", "")).lower()
        if receipt["accepted"] and login in accepted_by_login:
            receipt = deepcopy(receipt)
            receipt["accepted"] = False
            receipt["disposition"] = "REJECTED_DUPLICATE_LOGIN"
            receipt["problems"] = ["DUPLICATE_LOGIN_ALREADY_REGISTERED"]
            receipt["claim"] = None
            receipt.pop("receipt_hash", None)
            receipt["receipt_hash"] = stable_hash(receipt)
        elif receipt["accepted"]:
            accepted_by_login[login] = receipt["claim"]
        receipts.append(receipt)

    claims = sorted(
        accepted_by_login.values(),
        key=lambda claim: (claim["role"], claim["github_login"].lower()),
    )
    selector_logins = {
        claim["github_login"].lower()
        for claim in claims
        if claim["role"] == "selector_labeler"
    }
    auditor_logins = {
        claim["github_login"].lower()
        for claim in claims
        if claim["role"] == "reveal_auditor"
    }
    syntactic_two_role_candidate = bool(
        selector_logins
        and auditor_logins
        and any(a != b for a in selector_logins for b in auditor_logins)
    )

    registry = canonical({
        "schema": "arte.external_custodian_registration_registry/v1",
        "protocol_freeze_hash": PROTOCOL_FREEZE_HASH,
        "accepted_claims": claims,
        "receipts": receipts,
        "accepted_claim_count": len(claims),
        "selector_labeler_claims": len(selector_logins),
        "reveal_auditor_claims": len(auditor_logins),
        "syntactic_two_role_candidate": syntactic_two_role_candidate,
        "external_quorum_formed": False,
        "identity_independence_verified": False,
        "independent_external_successes": 0,
        "authority": (
            "CLAIM_SET_IDENTITY_UNVERIFIED"
            if claims
            else "NULL_NO_EXTERNAL_REGISTRATION"
        ),
        "promotion": False,
        "agi": False,
        "asi": False,
    })
    registry["registry_hash"] = stable_hash(registry)
    return registry


def render_receipt_markdown(receipt: Mapping[str, Any], registry: Mapping[str, Any]) -> str:
    if receipt.get("accepted"):
        claim = receipt["claim"]
        lines = [
            "### ARTE registration intake",
            "",
            "```text",
            "disposition  ACCEPTED_CLAIM_IDENTITY_UNVERIFIED",
            f"role         {claim['role']}",
            f"claim hash   {claim['registration_hash']}",
            f"registry     {registry['registry_hash']}",
            "```",
            "",
            "This validates syntax and protocol binding only. Identity, affiliation,",
            "independence, predictor isolation, external authority, and external success",
            "remain unverified.",
        ]
    else:
        lines = [
            "### ARTE registration intake",
            "",
            "```text",
            f"disposition  {receipt.get('disposition')}",
            f"receipt      {receipt.get('receipt_hash')}",
            "```",
            "",
            "Problems:",
            *[f"- `{problem}`" for problem in receipt.get("problems", [])],
            "",
            "No registration authority or progress credit was granted.",
        ]
    return "\n".join(lines) + "\n"
