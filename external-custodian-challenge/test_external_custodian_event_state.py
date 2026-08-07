import json
from copy import deepcopy
import external_custodian_event_state as sm


def fenced(payload): return "```json\n" + json.dumps(payload) + "\n```"


def verified_registry():
    row = {"schema":"arte.external_custodian_verified_registry/v1","registration_issue":3,"verified_custodians":[{"github_login":"alice","role":"selector_labeler","identity_verified":True,"independence_verified":True,"evidence_hash":"1"*64},{"github_login":"bob","role":"reveal_auditor","identity_verified":True,"independence_verified":True,"evidence_hash":"2"*64}],"identity_review_complete":True,"independence_review_complete":True,"external_quorum_formed":True,"authority":"VERIFIED_TWO_ROLE_CUSTODIAN_REGISTRY","promotion":False,"agi":False,"asi":False}
    row["registry_hash"] = sm.stable_hash(row); return row


def event(t,a,n,**fields):
    p={"event_type":t,"protocol_freeze_hash":sm.EVENT_PROTOCOL_FREEZE,"quorum_protocol_freeze_hash":sm.QUORUM_PROTOCOL_FREEZE,**fields}
    return {"id":n,"body":fenced(p),"author_login":a,"author_type":"User","created_at":f"2026-08-07T00:00:{n:02d}Z"}

CH="a"*64; SR="b"*64; AC="c"*64; PS="d"*64; RH="e"*64


def seq():
    return [event("selector_challenge_commit","alice",1,challenge_hash=CH,selector_reveal_hash=SR),event("auditor_reveal_hash_commit","bob",2,challenge_hash=CH,selector_reveal_hash=SR,auditor_commitment_hash=AC),event("prediction_seal","leehyen0",3,challenge_hash=CH,prediction_seal_hash=PS),event("selector_reveal","alice",4,challenge_hash=CH,selector_reveal_hash=SR,reveal_hash=RH),event("auditor_reveal_confirmation","bob",5,challenge_hash=CH,selector_reveal_hash=SR,auditor_commitment_hash=AC)]


def test_empty_registry_blocks_all_events():
    s=sm.build_state(registry=sm.empty_verified_registry(),comments=seq(),predictor_login="leehyen0")
    assert s["phase"]=="WAITING_FOR_VERIFIED_EXTERNAL_QUORUM" and s["accepted_event_count"]==0


def test_verified_complete_sequence_is_ordered_but_not_external_success():
    s=sm.build_state(registry=verified_registry(),comments=seq(),predictor_login="leehyen0")
    assert s["phase"]=="COMMIT_REVEAL_SEQUENCE_COMPLETE_CANDIDATE" and s["accepted_event_count"]==5
    assert s["sequence_complete_candidate"] and not s["independent_evaluation_complete"] and not s["external_success"]


def test_auditor_cannot_commit_before_selector():
    auditor=seq()[1]; auditor["created_at"]="2026-08-07T00:00:00Z"
    selector=seq()[0]; selector["created_at"]="2026-08-07T00:00:01Z"
    s=sm.build_state(registry=verified_registry(),comments=[auditor,selector],predictor_login="leehyen0")
    assert s["accepted_event_count"]==1 and any("EVENT_OUT_OF_ORDER" in r["problems"] for r in s["receipts"])


def test_selector_cannot_act_as_auditor():
    bad=event("auditor_reveal_hash_commit","alice",1,challenge_hash=CH,selector_reveal_hash=SR,auditor_commitment_hash=AC)
    s=sm.build_state(registry=verified_registry(),comments=[bad],predictor_login="leehyen0")
    assert "AUDITOR_ROLE_REQUIRED" in s["receipts"][0]["problems"]


def test_only_predictor_login_can_seal_predictions():
    rows=seq()[:2]+[event("prediction_seal","mallory",3,challenge_hash=CH,prediction_seal_hash=PS)]
    s=sm.build_state(registry=verified_registry(),comments=rows,predictor_login="leehyen0")
    assert s["accepted_event_count"]==2 and "PREDICTOR_LOGIN_REQUIRED" in s["receipts"][-1]["problems"]


def test_reference_wrong_swap_is_rejected():
    rows=seq()[:1]+[event("auditor_reveal_hash_commit","bob",2,challenge_hash="f"*64,selector_reveal_hash=SR,auditor_commitment_hash=AC)]
    s=sm.build_state(registry=verified_registry(),comments=rows,predictor_login="leehyen0")
    assert s["accepted_event_count"]==1 and "COMMIT_REFERENCE_MISMATCH" in s["receipts"][-1]["problems"]


def test_duplicate_event_type_is_rejected():
    rows=[seq()[0],dict(seq()[0],id=9,created_at="2026-08-07T00:00:09Z")]
    s=sm.build_state(registry=verified_registry(),comments=rows,predictor_login="leehyen0")
    assert s["accepted_event_count"]==1 and "DUPLICATE_EVENT_TYPE" in s["receipts"][-1]["problems"]


def test_private_material_is_rejected():
    row=seq()[0]; p=json.loads(row["body"].split("\n",1)[1].rsplit("\n",1)[0]); p["nonce"]="x"; row["body"]=fenced(p)
    s=sm.build_state(registry=verified_registry(),comments=[row],predictor_login="leehyen0")
    assert "PRIVATE_MATERIAL_FORBIDDEN" in s["receipts"][0]["problems"]


def test_tampered_registry_hash_blocks_quorum():
    r=verified_registry(); r["verified_custodians"][0]["role"]="reveal_auditor"
    s=sm.build_state(registry=r,comments=seq(),predictor_login="leehyen0")
    assert not s["verified_external_quorum"] and "REGISTRY_HASH_MISMATCH" in s["registry_problems"]


def test_two_verified_rows_same_login_are_invalid():
    r=verified_registry(); r["verified_custodians"][1]["github_login"]="alice"; raw=deepcopy(r); raw.pop("registry_hash"); r["registry_hash"]=sm.stable_hash(raw)
    s=sm.build_state(registry=r,comments=[],predictor_login="leehyen0")
    assert not s["verified_external_quorum"] and "DUPLICATE_VERIFIED_LOGIN" in s["registry_problems"]


def test_event_payload_with_surrounding_prose_is_rejected():
    row=seq()[0]; row["body"]="hello\n"+row["body"]
    s=sm.build_state(registry=verified_registry(),comments=[row],predictor_login="leehyen0")
    assert "SURROUNDING_PROSE_FORBIDDEN" in s["receipts"][0]["problems"]


def test_false_independence_claim_in_registry_blocks_quorum():
    r=verified_registry(); r["verified_custodians"][1]["independence_verified"]=False; raw=deepcopy(r); raw.pop("registry_hash"); r["registry_hash"]=sm.stable_hash(raw)
    s=sm.build_state(registry=r,comments=[],predictor_login="leehyen0")
    assert not s["verified_external_quorum"] and any(x.startswith("INDEPENDENCE_NOT_VERIFIED") for x in s["registry_problems"])
