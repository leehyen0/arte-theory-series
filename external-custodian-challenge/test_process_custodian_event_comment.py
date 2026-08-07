import json
import external_custodian_event_state as sm
import process_custodian_event_comment as proc


def raw_comment(cid, login, body, created="2026-08-07T00:00:00Z", user_type="User"):
    return {"id":cid,"body":body,"created_at":created,"html_url":f"synthetic://{cid}","user":{"login":login,"type":user_type}}


def event_payload():
    return {"event_type":"selector_challenge_commit","protocol_freeze_hash":sm.EVENT_PROTOCOL_FREEZE,"quorum_protocol_freeze_hash":sm.QUORUM_PROTOCOL_FREEZE,"challenge_hash":"a"*64,"selector_reveal_hash":"b"*64}


def fenced(payload): return "```json\n" + json.dumps(payload) + "\n```"


def event_obj(comment): return {"issue":{"number":8},"comment":comment}


def test_empty_production_registry_rejects_event_fail_closed():
    comment=raw_comment(1,"alice",fenced(event_payload()))
    receipt,state,markdown=proc.process(event=event_obj(comment),raw_comments=[comment],registry=sm.empty_verified_registry(),predictor_login="leehyen0")
    assert receipt["accepted"] is False
    assert receipt["problems"] == ["VERIFIED_EXTERNAL_QUORUM_REQUIRED"]
    assert state["phase"] == "WAITING_FOR_VERIFIED_EXTERNAL_QUORUM"
    assert "external success        false" in markdown


def test_bot_receipts_are_not_reingested_as_protocol_events():
    comment=raw_comment(1,"alice",fenced(event_payload()))
    bot=raw_comment(2,"github-actions[bot]","<!-- arte-custodian-event-receipt:1:deadbeef -->\nreceipt",created="2026-08-07T00:00:01Z",user_type="Bot")
    rows=proc.event_comments([comment,bot])
    assert len(rows)==1 and rows[0]["id"]==1


def test_target_comment_is_appended_if_fetch_snapshot_lags():
    comment=raw_comment(3,"alice",fenced(event_payload()))
    receipt,state,_=proc.process(event=event_obj(comment),raw_comments=[],registry=sm.empty_verified_registry(),predictor_login="leehyen0")
    assert receipt["source_comment_id"]==3
    assert state["accepted_event_count"]==0


def test_wrong_issue_event_is_rejected():
    comment=raw_comment(4,"alice",fenced(event_payload()))
    bad={"issue":{"number":3},"comment":comment}
    try:
        proc.process(event=bad,raw_comments=[comment],registry=sm.empty_verified_registry(),predictor_login="leehyen0")
    except ValueError as exc:
        assert str(exc)=="WRONG_EVENT_LEDGER_ISSUE"
    else:
        raise AssertionError("wrong issue was not rejected")


def test_idempotence_marker_detection():
    marker="<!-- arte-custodian-event-receipt:5:abc -->"
    comments=[raw_comment(8,"github-actions[bot]",marker+"\nresponse",user_type="Bot")]
    assert proc.already_posted(comments,marker) is True
