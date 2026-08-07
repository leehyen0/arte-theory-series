from __future__ import annotations
import argparse, json, re
from pathlib import Path
from typing import Any, Mapping

QUORUM_FREEZE="540f9b1087643580d21a162174a956e8a15d2ad2de2cc6c64b8bb02b612a0444"
EVENT_FREEZE="c6f5e17e8e77358c01ee87d3196659fdda44415b32ccd140190d1fc3c09dfdf2"
ROLES={"selector_labeler","reveal_auditor"}
REVIEW_TYPES={"identity","independence"}
EVENT_TYPES={"selector_challenge_commit","auditor_reveal_hash_commit","prediction_seal","selector_reveal","auditor_reveal_confirmation"}
EVIDENCE_KINDS={"github_account_control","non_github_identity_anchor","evaluation_independence"}
HEX64=re.compile(r"^[0-9a-f]{64}$")
PRIVATE_KEYS={"government_id","home_address","phone","private_email","private_contact","secret","secrets","nonce","nonces","private_reveal","private_tasks","expected_label","expected_labels","typed_transformation","typed_transformations","witness","witnesses","answer","answers"}

def _walk_private(value: Any,path="$"):
    found=[]
    if isinstance(value,Mapping):
        for k,v in value.items():
            ks=str(k)
            if ks.lower() in PRIVATE_KEYS: found.append(f"{path}.{ks}")
            found.extend(_walk_private(v,f"{path}.{ks}"))
    elif isinstance(value,list):
        for i,v in enumerate(value): found.extend(_walk_private(v,f"{path}[{i}]"))
    return found

def _hash(field,value,p):
    if not HEX64.fullmatch(str(value or "")): p.append(f"INVALID_SHA256:{field}")

def _exact_fields(payload,required,optional,p):
    keys=set(map(str,payload))
    missing=sorted(required-keys); extra=sorted(keys-required-optional)
    if missing: p.append("MISSING_FIELDS:"+",".join(missing))
    if extra: p.append("UNEXPECTED_FIELDS:"+",".join(extra))

def validate_registration(payload):
    p=[]
    _exact_fields(payload,{"github_login","role","affiliation","conflict_disclosure","public_key_fingerprint","protocol_freeze_hash","attests_no_predictor_access"},set(),p)
    if payload.get("role") not in ROLES: p.append("UNSUPPORTED_ROLE")
    if payload.get("protocol_freeze_hash")!=QUORUM_FREEZE: p.append("PROTOCOL_FREEZE_MISMATCH")
    if payload.get("attests_no_predictor_access") is not True: p.append("PREDICTOR_ACCESS_ATTESTATION_REQUIRED")
    for f in ("github_login","affiliation","conflict_disclosure"):
        if not isinstance(payload.get(f),str) or not str(payload.get(f)).strip(): p.append(f"NONEMPTY_STRING_REQUIRED:{f}")
    if not isinstance(payload.get("public_key_fingerprint"),str): p.append("STRING_REQUIRED:public_key_fingerprint")
    private=_walk_private(payload)
    if private: p.append("PRIVATE_MATERIAL_FORBIDDEN:"+",".join(private))
    p+=["SERVER_CHECK_REQUIRED:COMMENT_AUTHOR_MUST_EQUAL_GITHUB_LOGIN","SERVER_CHECK_REQUIRED:OWNER_BOT_DUPLICATE_LOGIN"]
    return p

def validate_evidence_bundle(payload):
    p=[]
    _exact_fields(payload,{"event_type","protocol_freeze_hash","subject_login","subject_role","registration_receipt_hash","conflict_disclosure","evidence"},{"submitted_at"},p)
    if payload.get("event_type")!="evidence_bundle": p.append("EVENT_TYPE_MUST_BE:evidence_bundle")
    if payload.get("protocol_freeze_hash")!=QUORUM_FREEZE: p.append("PROTOCOL_FREEZE_MISMATCH")
    if payload.get("subject_role") not in ROLES: p.append("UNSUPPORTED_ROLE")
    _hash("registration_receipt_hash",payload.get("registration_receipt_hash"),p)
    evidence=payload.get("evidence")
    if not isinstance(evidence,list):
        p.append("EVIDENCE_LIST_REQUIRED"); evidence=[]
    kinds=[]; digests=[]
    for i,row in enumerate(evidence):
        if not isinstance(row,Mapping): p.append(f"INVALID_EVIDENCE_ROW:{i}"); continue
        _exact_fields(row,{"kind","artifact_sha256","public_locator"},set(),p)
        kind=str(row.get("kind","")); kinds.append(kind)
        if kind not in EVIDENCE_KINDS: p.append(f"UNSUPPORTED_EVIDENCE_KIND:{i}")
        digest=str(row.get("artifact_sha256","")); _hash(f"evidence[{i}].artifact_sha256",digest,p)
        if HEX64.fullmatch(digest): digests.append(digest)
        if kind!="evaluation_independence" and not str(row.get("public_locator","")).strip(): p.append(f"PUBLIC_LOCATOR_REQUIRED:{i}")
    for kind in sorted(EVIDENCE_KINDS):
        if kind not in kinds: p.append(f"MISSING_EVIDENCE_KIND:{kind}")
    if len(digests)!=len(set(digests)): p.append("DUPLICATE_EVIDENCE_SHA256_WITHIN_BUNDLE")
    private=_walk_private(payload)
    if private: p.append("PRIVATE_MATERIAL_FORBIDDEN:"+",".join(private))
    p+=["SERVER_CHECK_REQUIRED:SUBJECT_MUST_HAVE_ACCEPTED_REGISTRATION","SERVER_CHECK_REQUIRED:AUTHOR_MUST_EQUAL_SUBJECT_LOGIN","SERVER_CHECK_REQUIRED:REGISTRATION_RECEIPT_MUST_EXIST_AND_MATCH_ROLE"]
    return p

def validate_review(payload):
    p=[]
    _exact_fields(payload,{"event_type","protocol_freeze_hash","subject_login","review_type","evidence_bundle_hash","decision","attests_reviewed_evidence","attests_no_conflict","attests_distinct_human_to_best_knowledge","attests_no_shared_control_for_evaluation","reviewer_conflict_disclosure"},{"submitted_at"},p)
    if payload.get("event_type")!="review_attestation": p.append("EVENT_TYPE_MUST_BE:review_attestation")
    if payload.get("protocol_freeze_hash")!=QUORUM_FREEZE: p.append("PROTOCOL_FREEZE_MISMATCH")
    if payload.get("review_type") not in REVIEW_TYPES: p.append("UNSUPPORTED_REVIEW_TYPE")
    _hash("evidence_bundle_hash",payload.get("evidence_bundle_hash"),p)
    if payload.get("decision")!="support": p.append("SUPPORT_DECISION_REQUIRED")
    for f in ("attests_reviewed_evidence","attests_no_conflict","attests_distinct_human_to_best_knowledge"):
        if payload.get(f) is not True: p.append(f"TRUE_REQUIRED:{f}")
    if payload.get("review_type")=="independence" and payload.get("attests_no_shared_control_for_evaluation") is not True:
        p.append("TRUE_REQUIRED:attests_no_shared_control_for_evaluation")
    private=_walk_private(payload)
    if private: p.append("PRIVATE_MATERIAL_FORBIDDEN:"+",".join(private))
    p+=["SERVER_CHECK_REQUIRED:REVIEWER_MUST_NOT_BE_SUBJECT_OWNER_BOT_OR_CUSTODIAN_CANDIDATE","SERVER_CHECK_REQUIRED:EVIDENCE_BUNDLE_HASH_MUST_EXIST","SERVER_CHECK_REQUIRED:IDENTITY_AND_INDEPENDENCE_REVIEWERS_MUST_DIFFER"]
    return p

def validate_protocol_event(payload):
    p=[]; event_type=str(payload.get("event_type",""))
    if event_type not in EVENT_TYPES: return ["UNSUPPORTED_EVENT_TYPE"]
    required_by_type={
      "selector_challenge_commit":{"challenge_hash","selector_reveal_hash"},
      "auditor_reveal_hash_commit":{"challenge_hash","selector_reveal_hash","auditor_commitment_hash"},
      "prediction_seal":{"challenge_hash","prediction_seal_hash"},
      "selector_reveal":{"challenge_hash","selector_reveal_hash","reveal_hash"},
      "auditor_reveal_confirmation":{"challenge_hash","selector_reveal_hash","auditor_commitment_hash"}}
    base={"event_type","protocol_freeze_hash","quorum_protocol_freeze_hash"}
    _exact_fields(payload,base|required_by_type[event_type],{"submitted_at"},p)
    if payload.get("protocol_freeze_hash")!=EVENT_FREEZE: p.append("EVENT_PROTOCOL_FREEZE_MISMATCH")
    if payload.get("quorum_protocol_freeze_hash")!=QUORUM_FREEZE: p.append("QUORUM_PROTOCOL_FREEZE_MISMATCH")
    for f in required_by_type[event_type]: _hash(f,payload.get(f),p)
    private=_walk_private(payload)
    if private: p.append("PRIVATE_MATERIAL_FORBIDDEN:"+",".join(private))
    p+=["SERVER_CHECK_REQUIRED:LIVE_EVIDENCE_REVIEWED_QUORUM","SERVER_CHECK_REQUIRED:ACTOR_ROLE_BINDING_AND_EVENT_ORDER","SERVER_CHECK_REQUIRED:CROSS_EVENT_HASH_REFERENCES"]
    return p

VALIDATORS={"registration":validate_registration,"evidence":validate_evidence_bundle,"review":validate_review,"event":validate_protocol_event}

def split(problems):
    return ([x for x in problems if not x.startswith("SERVER_CHECK_REQUIRED:")],[x for x in problems if x.startswith("SERVER_CHECK_REQUIRED:")])

def example(kind):
    if kind=="registration":
        return {"github_login":"your-login","role":"selector_labeler","affiliation":"independent","conflict_disclosure":"none","public_key_fingerprint":"","protocol_freeze_hash":QUORUM_FREEZE,"attests_no_predictor_access":True}
    if kind=="evidence":
        return {"event_type":"evidence_bundle","protocol_freeze_hash":QUORUM_FREEZE,"subject_login":"your-login","subject_role":"selector_labeler","registration_receipt_hash":"a"*64,"conflict_disclosure":"none","evidence":[{"kind":"github_account_control","artifact_sha256":"b"*64,"public_locator":"https://example.invalid/account-control"},{"kind":"non_github_identity_anchor","artifact_sha256":"c"*64,"public_locator":"https://example.invalid/identity-anchor"},{"kind":"evaluation_independence","artifact_sha256":"d"*64,"public_locator":""}]}
    if kind=="review":
        return {"event_type":"review_attestation","protocol_freeze_hash":QUORUM_FREEZE,"subject_login":"candidate-login","review_type":"identity","evidence_bundle_hash":"e"*64,"decision":"support","attests_reviewed_evidence":True,"attests_no_conflict":True,"attests_distinct_human_to_best_knowledge":True,"attests_no_shared_control_for_evaluation":True,"reviewer_conflict_disclosure":"none"}
    return {"event_type":"selector_challenge_commit","protocol_freeze_hash":EVENT_FREEZE,"quorum_protocol_freeze_hash":QUORUM_FREEZE,"challenge_hash":"f"*64,"selector_reveal_hash":"1"*64}

def main():
    ap=argparse.ArgumentParser(description="Local preflight for ARTE external-Custodian submissions.")
    ap.add_argument("kind",choices=sorted(VALIDATORS)); ap.add_argument("file",nargs="?"); ap.add_argument("--example",action="store_true")
    a=ap.parse_args()
    if a.example:
        print(json.dumps(example(a.kind),indent=2)); return 0
    if not a.file: ap.error("file is required unless --example is used")
    payload=json.loads(Path(a.file).read_text(encoding="utf-8"))
    if not isinstance(payload,dict): raise SystemExit("top-level JSON object required")
    local,server=split(VALIDATORS[a.kind](payload))
    print(json.dumps({"kind":a.kind,"local_preflight_pass":not local,"local_problems":local,"server_checks_still_required":server,"authority_granted":False,"independent_evaluation":False,"external_success":False,"promotion":False,"agi":False,"asi":False},indent=2,sort_keys=True))
    return 0 if not local else 2
if __name__=="__main__": raise SystemExit(main())
