from copy import deepcopy
import pytest
import public_custodian_verifier as V


def fixture():
    issue=("A wide glyph leaves the cursor in the wrong cell after render. "
           "Moving over the glyph triggers the failure. ASCII text is unaffected. "
           "The renderer advances one cell instead of the rendered cell span.")
    source={"commit":"1"*40,"path":"src/render.rs","blob_sha":"2"*40,
            "excerpt":"advance by the rendered cell span"}
    public={"repository":"example/terminal","issue_number":1,"implementation_language":"Rust",
            "title":"Wide glyph cursor is misplaced","issue_body":issue,"comments":[],"source":source}
    public["task_id"]=V.stable_hash(public)
    witnesses={
      "observed_failure":{"channel":"issue","span":"the cursor in the wrong cell"},
      "intervention_or_trigger":{"channel":"issue","span":"moving over the glyph triggers the failure"},
      "counterfactual_or_control":{"channel":"issue","span":"ascii text is unaffected"},
      "causal_locus_claim":{"channel":"issue","span":"the renderer advances one cell instead of the rendered cell span"},
      "source_ownership_witness":{"channel":"source","span":"advance by the rendered cell span"}}
    led=V.build_typed_ledger(repository=public["repository"],issue_number=1,title=public["title"],
        issue_body=issue,comments=[],source=source,witnesses=witnesses,
        transformations=["advance_physical_cell_span"])
    private={"task_id":public["task_id"],"nonce":"synthetic-test-nonce","witnesses":witnesses,
        "typed_transformations":["advance_physical_cell_span"],"feature_only":False,
        "locus_contested":False,"unsupported_domain":None,"expected_commitment":led["commitment"],
        "expected_reason":led["reason"],"ledger_hash":led["ledger_hash"]}
    pf,rf,rs="a"*64,"b"*64,"c"*64; secret="synthetic-test-selector-secret"
    payload={"protocol_freeze_hash":pf,"router_freeze_hash":rf,"router_source_sha256":rs,
             "public_task_hash":V.stable_hash(public),"private_task":private}
    public["private_commitment_hmac_sha256"]=V.hmac_sha256(secret,payload)
    challenge={"schema":"arte.external_custodian_public_challenge/v1",
        "protocol_schema":"arte.external_custodian_blind_protocol/v1","protocol_freeze_hash":pf,
        "router_freeze_hash":rf,"router_source_sha256":rs,"custodian_id":"selector-A",
        "selected_at":"now","task_count":1,"tasks":[public],"independent_custodian_claimed":True,
        "labels_or_transformations_public":False,"patch_authority":False,"progress_credit":0}
    challenge["challenge_hash"]=V.stable_hash(challenge)
    reveal={"schema":"arte.external_custodian_private_reveal/v1",
        "protocol_schema":"arte.external_custodian_blind_protocol/v1",
        "challenge_hash":challenge["challenge_hash"],"custodian_id":"selector-A",
        "custodian_secret":secret,"private_tasks":[private],"ledger_hashes":[led["ledger_hash"]],
        "independent_custodian_attestation":True,"reveal_must_follow_prediction_seal":True}
    reveal["reveal_hash"]=V.stable_hash(reveal)
    prediction={"schema":"arte.external_custodian_prediction_seal/v1",
        "protocol_schema":"arte.external_custodian_blind_protocol/v1",
        "challenge_hash":challenge["challenge_hash"],"predictor_id":"frozen-router",
        "predicted_at":"later","router_freeze_hash":rf,"router_source_sha256":rs,
        "predictions":[{"task_id":public["task_id"],"prediction":"physical_cursor_advance_after_render",
                        "reason_code":"FROZEN_OUTPUT","confidence":0.8,"latency_ms":1.0}],
        "private_reveal_seen":False,"patch_authority":False,"progress_credit":0}
    prediction["prediction_seal_hash"]=V.stable_hash(prediction)
    return challenge,prediction,reveal


def test_round_trip():
    c,p,r=fixture(); s=V.verify_selector_reveal_and_score(challenge=c,prediction_seal=p,reveal=r,scored_at="later")
    assert s["eligible_exact_rate"]==1.0 and s["independent_external_successes"]==0


def test_public_mutation_rejected():
    c,p,r=fixture(); c=deepcopy(c); c["tasks"][0]["issue_body"]+=" tampered"
    with pytest.raises(ValueError,match="challenge_hash mismatch"):
        V.verify_selector_reveal_and_score(challenge=c,prediction_seal=p,reveal=r,scored_at="later")


def test_reveal_exposure_rejected():
    c,p,r=fixture(); p=deepcopy(p); p["private_reveal_seen"]=True
    p.pop("prediction_seal_hash"); p["prediction_seal_hash"]=V.stable_hash(p)
    with pytest.raises(ValueError,match="reveal exposure"):
        V.verify_selector_reveal_and_score(challenge=c,prediction_seal=p,reveal=r,scored_at="later")


def test_rehashed_private_mutation_breaks_hmac():
    c,p,r=fixture(); r=deepcopy(r); r["private_tasks"][0]["nonce"]="changed"
    r.pop("reveal_hash"); r["reveal_hash"]=V.stable_hash(r)
    with pytest.raises(ValueError,match="selector commitment mismatch"):
        V.verify_selector_reveal_and_score(challenge=c,prediction_seal=p,reveal=r,scored_at="later")


def test_private_key_scan():
    assert V.scan_private_keys({"task":{"expected_commitment":"synthetic-test-value"}})==["$.task.expected_commitment"]


def test_invalid_witness_is_unknown():
    c,_,_=fixture(); t=c["tasks"][0]; w={role:{"channel":"issue","span":"missing"} for role in V.ROLES}
    led=V.build_typed_ledger(repository=t["repository"],issue_number=1,title=t["title"],issue_body=t["issue_body"],
        comments=[],source=t["source"],witnesses=w,transformations=["advance_physical_cell_span"])
    assert led["commitment"]=="UNKNOWN"


def test_registration_cannot_self_verify_independence():
    reg={"schema":"arte.external_custodian_registration/v1","custodian_id":"github:alice:1",
        "github_login":"alice","role":"selector_labeler","affiliation":"independent",
        "conflict_disclosure":"none","public_key_fingerprint":"sha256:test",
        "protocol_freeze_hash":"a"*64,"registered_at":"now","attests_no_predictor_access":True,
        "identity_verified":False,"affiliation_verified":False,"independence_verified":True}
    reg["registration_hash"]=V.stable_hash(reg)
    with pytest.raises(ValueError,match="cannot self-verify independence"):
        V.verify_registration(reg,"a"*64)
