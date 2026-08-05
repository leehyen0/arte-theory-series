"""Dependency-free verifier for the public ARTE custodian challenge.

It verifies canonical SHA-256 hashes, selector/auditor HMAC commitments,
typed causal witness ledgers, prediction seals and two-role quorum references.
It does not verify human identity or grant external-success credit.
"""
from __future__ import annotations
import hashlib, hmac, json, re
from typing import Any, Mapping, Sequence

TRANSFORM = {
    "advance_physical_cell_span": "physical_cursor_advance_after_render",
    "allocate_terminal_cell_count": "terminal_width_model_authority",
    "map_logical_row_to_visual_row": "logical_to_wrapped_visual_row",
    "map_visual_cell_to_text_boundary": "visual_cell_to_grapheme_boundary",
    "shape_cluster_geometry": "font_shaping_cluster_geometry",
}
ROLES = ("observed_failure", "intervention_or_trigger", "counterfactual_or_control",
         "causal_locus_claim", "source_ownership_witness")
ALLOWED = frozenset((*TRANSFORM.values(), "UNKNOWN", "INELIGIBLE"))
PRIVATE = frozenset({"witnesses", "transformations", "typed_transformations",
    "expected_authority", "expected_commitment", "feature_only", "locus_contested",
    "unsupported_domain", "nonce", "secret", "answer", "label", "reveal",
    "private_reveal", "private_tasks"})


def canonical(v: Any) -> Any:
    if isinstance(v, Mapping):
        return {str(k): canonical(v[k]) for k in sorted(v, key=lambda x: str(x))}
    if isinstance(v, (list, tuple)): return [canonical(x) for x in v]
    if isinstance(v, set): return [canonical(x) for x in sorted(v, key=repr)]
    return v


def packed(v: Any) -> bytes:
    return json.dumps(canonical(v), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


def digest(v: Any) -> str:
    data = v if isinstance(v, bytes) else (v.encode() if isinstance(v, str) else packed(v))
    return hashlib.sha256(data).hexdigest()


def mac(secret: str, v: Any) -> str:
    return hmac.new(secret.encode(), packed(v), hashlib.sha256).hexdigest()


def embedded(v: Mapping[str, Any], field: str) -> str:
    row = canonical(dict(v)); observed = row.pop(field, None)
    if observed != digest(row): raise ValueError(f"{field} mismatch")
    return str(observed)


def private_paths(v: Any, path: str = "$") -> list[str]:
    out = []
    if isinstance(v, Mapping):
        for k, child in v.items():
            if str(k).lower() in PRIVATE: out.append(f"{path}.{k}")
            out.extend(private_paths(child, f"{path}.{k}"))
    elif isinstance(v, (list, tuple)):
        for i, child in enumerate(v): out.extend(private_paths(child, f"{path}[{i}]"))
    return out


def norm(v: Any) -> str:
    return re.sub(r"\s+", " ", str(v or "").lower()).strip()


def ledger(*, repository: str, issue_number: int, title: str, issue_body: str,
           comments: Sequence[str], source: Mapping[str, Any],
           witnesses: Mapping[str, Mapping[str, Any]], transformations: Sequence[str],
           feature_only: bool = False, locus_contested: bool = False,
           unsupported_domain: str | None = None) -> dict[str, Any]:
    issue = norm(f"{title}\n{issue_body}"); comments_n = norm("\n".join(comments))
    source = dict(source); source_n = norm(f"{source.get('path','')}\n{source.get('excerpt','')}")
    channels = {"issue": issue, "comments": comments_n, "source": source_n}
    normalized, invalid = {}, []
    for role in ROLES:
        raw = dict(witnesses.get(role, {})); channel = str(raw.get("channel", "")); span = norm(raw.get("span", ""))
        contained = bool(channel in channels and span and span in channels[channel])
        if not contained: invalid.append({"role": role, "channel": channel, "span": span})
        normalized[role] = canonical({"channel": channel, "span": span,
            "span_sha256": digest(span), "contained_in_committed_channel": contained})
    source_ok = bool(source.get("commit") and source.get("path") and source.get("blob_sha"))
    tx = list(dict.fromkeys(map(str, transformations)))
    unknown = [x for x in tx if x not in TRANSFORM and x != "unsupported"]
    authorities = [TRANSFORM[x] for x in tx if x in TRANSFORM]
    if feature_only: commitment, reason = "INELIGIBLE", "FEATURE_ONLY_WITHOUT_OBSERVED_FAILURE"
    elif invalid: commitment, reason = "UNKNOWN", "WITNESS_LEDGER_INVALID_OR_INCOMPLETE"
    elif not source_ok: commitment, reason = "UNKNOWN", "SOURCE_CUSTODY_INCOMPLETE"
    elif unsupported_domain: commitment, reason = "UNKNOWN", f"UNSUPPORTED_DOMAIN:{unsupported_domain}"
    elif locus_contested: commitment, reason = "UNKNOWN", "CAUSAL_LOCUS_EXTERNAL_OR_CONTESTED"
    elif unknown: commitment, reason = "UNKNOWN", "UNREGISTERED_TYPED_TRANSFORMATION"
    elif len(authorities) != 1: commitment, reason = "UNKNOWN", "NO_UNIQUE_MINIMUM_SUFFICIENT_TYPED_TRANSFORMATION"
    else: commitment, reason = authorities[0], "UNIQUE_TYPED_CAUSAL_CUSTODY_AUTHORITY"
    row = canonical({"schema":"arte.typed_causal_witness_ledger/v1", "repository":repository,
        "issue_number":int(issue_number), "title":title, "issue_sha256":digest(issue),
        "comments_sha256":digest(comments_n), "source":{"commit":source.get("commit"),
        "path":source.get("path"), "blob_sha":source.get("blob_sha"),
        "excerpt_sha256":digest(source_n), "custody_complete":source_ok},
        "witnesses":normalized, "invalid_witnesses":invalid, "typed_transformations":tx,
        "mapped_authorities":authorities, "unknown_transformations":unknown,
        "feature_only":bool(feature_only), "locus_contested":bool(locus_contested),
        "unsupported_domain":unsupported_domain, "commitment":commitment, "reason":reason,
        "independent_custodian":False, "independent_evaluation":False,
        "patch_authority":False, "promotion":False, "agi":False, "asi":False})
    row["ledger_hash"] = digest(row); return row


def challenge_info(challenge: Mapping[str, Any]) -> dict[str, Any]:
    challenge = canonical(dict(challenge)); ch = embedded(challenge, "challenge_hash")
    hits = [x for x in private_paths(challenge) if x != "$.labels_or_transformations_public"]
    if hits: raise ValueError(f"private material in public challenge: {hits}")
    tasks = challenge.get("tasks", [])
    if len(tasks) != int(challenge.get("task_count", -1)): raise ValueError("task count mismatch")
    ids = []
    for task in tasks:
        base = {k:v for k,v in task.items() if k not in {"task_id","private_commitment_hmac_sha256"}}
        if task.get("task_id") != digest(canonical(base)): raise ValueError("task id mismatch")
        if task["task_id"] in ids: raise ValueError("duplicate task")
        ids.append(task["task_id"])
    return {"challenge_hash":ch, "task_ids":ids}


def prediction_hash(challenge: Mapping[str, Any], seal: Mapping[str, Any]) -> str:
    info = challenge_info(challenge); seal = canonical(dict(seal)); ph = embedded(seal, "prediction_seal_hash")
    if seal.get("challenge_hash") != info["challenge_hash"]: raise ValueError("wrong challenge")
    if seal.get("router_freeze_hash") != challenge.get("router_freeze_hash"): raise ValueError("wrong router freeze")
    if seal.get("router_source_sha256") != challenge.get("router_source_sha256"): raise ValueError("wrong router source")
    if seal.get("private_reveal_seen") is not False: raise ValueError("reveal exposure")
    rows = seal.get("predictions", [])
    if [x.get("task_id") for x in rows] != info["task_ids"]: raise ValueError("prediction task mismatch")
    if any(x.get("prediction") not in ALLOWED for x in rows): raise ValueError("unsupported prediction")
    return ph


def score(challenge: Mapping[str, Any], prediction: Mapping[str, Any], reveal: Mapping[str, Any], scored_at: str) -> dict[str, Any]:
    info = challenge_info(challenge); ph = prediction_hash(challenge, prediction)
    reveal = canonical(dict(reveal)); rh = embedded(reveal, "reveal_hash")
    if reveal.get("challenge_hash") != info["challenge_hash"]: raise ValueError("wrong reveal challenge")
    pub = {x["task_id"]:x for x in challenge["tasks"]}; priv = {x["task_id"]:x for x in reveal.get("private_tasks",[])}
    pred = {x["task_id"]:x for x in prediction["predictions"]}
    if not (set(pub)==set(priv)==set(pred)): raise ValueError("task sets differ")
    secret = str(reveal.get("custodian_secret", ""))
    if len(secret) < 16: raise ValueError("selector secret missing")
    rows, hashes = [], []
    for tid in info["task_ids"]:
        p, r = pub[tid], priv[tid]
        public_without = {k:v for k,v in p.items() if k != "private_commitment_hmac_sha256"}
        payload = canonical({"protocol_freeze_hash":challenge["protocol_freeze_hash"],
            "router_freeze_hash":challenge["router_freeze_hash"],
            "router_source_sha256":challenge["router_source_sha256"],
            "public_task_hash":digest(public_without), "private_task":r})
        if not hmac.compare_digest(mac(secret,payload), str(p.get("private_commitment_hmac_sha256",""))):
            raise ValueError(f"selector commitment mismatch for {tid}")
        led = ledger(repository=p["repository"], issue_number=p["issue_number"], title=p["title"],
            issue_body=p["issue_body"], comments=p["comments"], source=p["source"],
            witnesses=r["witnesses"], transformations=r["typed_transformations"],
            feature_only=r["feature_only"], locus_contested=r["locus_contested"],
            unsupported_domain=r["unsupported_domain"])
        if (led["ledger_hash"],led["commitment"],led["reason"]) != (r.get("ledger_hash"),r.get("expected_commitment"),r.get("expected_reason")):
            raise ValueError(f"ledger mismatch for {tid}")
        hashes.append(led["ledger_hash"]); expected, actual = led["commitment"], pred[tid]["prediction"]
        if expected=="INELIGIBLE": cls = "correct_ineligible" if actual==expected else "ineligible_false_positive"
        elif expected=="UNKNOWN" and actual=="UNKNOWN": cls="correct_unknown"
        elif expected=="UNKNOWN": cls="false_positive_wrong_swap"
        elif actual==expected: cls="correct_known_authority"
        elif actual=="UNKNOWN": cls="safe_abstention_on_known"
        else: cls="incorrect_authority"
        rows.append(canonical({"task_id":tid,"expected":expected,"predicted":actual,"classification":cls,"ledger_hash":led["ledger_hash"]}))
    if hashes != list(reveal.get("ledger_hashes",[])): raise ValueError("ledger order mismatch")
    eligible=[x for x in rows if x["expected"]!="INELIGIBLE"]; exact=sum(x["expected"]==x["predicted"] for x in eligible)
    out=canonical({"schema":"arte.public_external_custodian_verifier_score/v1",
        "challenge_hash":info["challenge_hash"],"prediction_seal_hash":ph,"reveal_hash":rh,
        "scored_at":str(scored_at),"task_count":len(rows),"eligible_task_count":len(eligible),
        "total_exact_correct":sum(x["expected"]==x["predicted"] for x in rows),
        "total_exact_rate":sum(x["expected"]==x["predicted"] for x in rows)/max(1,len(rows)),
        "eligible_exact_correct":exact,"eligible_exact_rate":exact/max(1,len(eligible)),
        "ineligible_false_positive":sum(x["classification"]=="ineligible_false_positive" for x in rows),
        "false_positive_wrong_swap":sum(x["classification"]=="false_positive_wrong_swap" for x in rows),
        "rows":rows,"identity_independence_verified":False,"classification_only":True,
        "independent_external_successes":0,"patch_authority":False,"progress_vector_changed":False,
        "promotion":False,"agi":False,"asi":False})
    out["score_hash"] = digest(out); return out

stable_hash = digest
hmac_sha256 = mac
scan_private_keys = private_paths
build_typed_ledger = ledger

def verify_selector_reveal_and_score(*, challenge, prediction_seal, reveal, scored_at):
    return score(challenge, prediction_seal, reveal, scored_at)

def verify_registration(registration: Mapping[str, Any], protocol_freeze_hash: str) -> str:
    registration = canonical(dict(registration)); rh = embedded(registration, "registration_hash")
    if registration.get("protocol_freeze_hash") != protocol_freeze_hash:
        raise ValueError("registration protocol freeze mismatch")
    if registration.get("role") not in {"selector_labeler", "reveal_auditor", "timestamp_witness"}:
        raise ValueError("unsupported registration role")
    if registration.get("identity_verified") is not False:
        raise ValueError("public registration cannot self-verify identity")
    if registration.get("independence_verified") is not False:
        raise ValueError("public registration cannot self-verify independence")
    return rh
