from __future__ import annotations

from pathlib import Path
from typing import Any
import argparse
import json
import os
import urllib.request

import public_registration_intake as registration
import identity_independence_promotion as promotion

RECEIPT_MARKER = "<!-- arte-identity-independence-review:"


def api_request(url: str, token: str, *, method: str = "GET", payload: Any = None) -> Any:
    data = None
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "arte-identity-independence-review"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        data = json.dumps(payload).encode(); headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as response:
        body = response.read(); return json.loads(body) if body else None


def fetch_issue_comments(repository: str, issue_number: int, token: str) -> list[dict[str, Any]]:
    out=[]; page=1
    while True:
        url=f"https://api.github.com/repos/{repository}/issues/{issue_number}/comments?per_page=100&page={page}"
        batch=api_request(url, token)
        if not isinstance(batch, list):
            raise RuntimeError("GitHub comments response is not a list")
        out.extend(batch)
        if len(batch)<100: break
        page+=1
    return out


def normalize_registration_comments(raw_comments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows=[]
    for raw in raw_comments:
        user=raw.get("user") or {}; login=str(user.get("login", "")); body=str(raw.get("body", ""))
        if login.endswith("[bot]") or "<!-- arte-registration-intake:" in body: continue
        rows.append({"id":int(raw.get("id",0)),"body":body,"author_login":login,"author_type":str(user.get("type","")),"html_url":str(raw.get("html_url","")),"created_at":str(raw.get("created_at","")),"issue_number":registration.REGISTRATION_ISSUE_NUMBER})
    return rows


def normalize_review_comments(raw_comments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows=[]
    for raw in raw_comments:
        user=raw.get("user") or {}; login=str(user.get("login", "")); body=str(raw.get("body", ""))
        if login.endswith("[bot]") or RECEIPT_MARKER in body: continue
        rows.append({"id":int(raw.get("id",0)),"body":body,"author_login":login,"author_type":str(user.get("type","")),"html_url":str(raw.get("html_url","")),"created_at":str(raw.get("created_at",""))})
    return rows


def rebuild_state(*, raw_registration_comments: list[dict[str, Any]], raw_review_comments: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    registration_registry=registration.build_registry(normalize_registration_comments(raw_registration_comments))
    state=promotion.build_promotion_state(registration_receipts=registration_registry["receipts"],comments=normalize_review_comments(raw_review_comments))
    state["registration_registry_hash"]=registration_registry["registry_hash"]
    state.pop("state_hash",None); state["state_hash"]=promotion.stable_hash(state)
    return registration_registry,state


def render_response(receipt: dict[str, Any], state: dict[str, Any]) -> str:
    registry=state["verified_registry"]
    lines=["### ARTE identity / independence evidence review","",f"- accepted ledger event: `{str(receipt.get('accepted',False)).lower()}`",f"- disposition: `{receipt.get('disposition')}`",f"- promoted custodians: `{state.get('promoted_custodian_count',0)}`",f"- evidence-reviewed external quorum candidate: `{str(registry.get('external_quorum_formed',False)).lower()}`",f"- registry hash: `{registry.get('registry_hash')}`",f"- state hash: `{state.get('state_hash')}`",f"- receipt hash: `{receipt.get('receipt_hash')}`"]
    if receipt.get("problems"): lines += ["","Problems:",*([f"- `{x}`" for x in receipt["problems"]])]
    lines += ["","```text","absolute human uniqueness proven  false","absolute independence proven      false","independent evaluation complete   false","external success                  false","promotion                         false","AGI / ASI                         false / false","```"]
    return "\n".join(lines)+"\n"


def process(*, event: dict[str, Any], raw_registration_comments: list[dict[str, Any]], raw_review_comments: list[dict[str, Any]]) -> tuple[dict[str, Any],dict[str, Any],dict[str, Any],str]:
    issue=event.get("issue") or {}; current=event.get("comment") or {}
    if int(issue.get("number",0)) != promotion.EVIDENCE_REVIEW_ISSUE_NUMBER: raise ValueError("WRONG_EVIDENCE_REVIEW_ISSUE")
    cid=int(current.get("id",0))
    if not any(int(row.get("id",0))==cid for row in raw_review_comments): raw_review_comments=[*raw_review_comments,current]
    registration_registry,state=rebuild_state(raw_registration_comments=raw_registration_comments,raw_review_comments=raw_review_comments)
    matches=[r for r in state["receipts"] if int(r.get("source_comment_id",0))==cid]
    if len(matches)!=1: raise RuntimeError("TARGET_REVIEW_RECEIPT_NOT_UNIQUE")
    receipt=matches[0]
    return receipt,registration_registry,state,render_response(receipt,state)


def already_posted(raw_comments: list[dict[str, Any]], marker: str) -> bool:
    return any(marker in str(x.get("body","")) for x in raw_comments)


def main() -> None:
    p=argparse.ArgumentParser(); p.add_argument("--event",required=True); p.add_argument("--repository",default=os.environ.get("GITHUB_REPOSITORY","")); p.add_argument("--token",default=os.environ.get("GITHUB_TOKEN","")); p.add_argument("--registration-comments-json"); p.add_argument("--review-comments-json"); p.add_argument("--output-dir",required=True); p.add_argument("--post-response",action="store_true"); a=p.parse_args()
    event=json.loads(Path(a.event).read_text())
    raw_reg=json.loads(Path(a.registration_comments_json).read_text()) if a.registration_comments_json else fetch_issue_comments(a.repository,registration.REGISTRATION_ISSUE_NUMBER,a.token)
    raw_review=json.loads(Path(a.review_comments_json).read_text()) if a.review_comments_json else fetch_issue_comments(a.repository,promotion.EVIDENCE_REVIEW_ISSUE_NUMBER,a.token)
    receipt,registration_registry,state,markdown=process(event=event,raw_registration_comments=raw_reg,raw_review_comments=raw_review)
    cid=int((event.get("comment") or {}).get("id",0)); marker=f"{RECEIPT_MARKER}{cid}:{receipt['receipt_hash']} -->"; response=marker+"\n"+markdown
    out=Path(a.output_dir); out.mkdir(parents=True,exist_ok=True)
    (out/"review_receipt.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    (out/"registration_registry.json").write_text(json.dumps(registration_registry,indent=2,sort_keys=True)+"\n")
    (out/"promotion_state.json").write_text(json.dumps(state,indent=2,sort_keys=True)+"\n")
    (out/"verified_custodian_registry.json").write_text(json.dumps(state["verified_registry"],indent=2,sort_keys=True)+"\n")
    (out/"review_response.md").write_text(response)
    posted=False
    if a.post_response and not already_posted(raw_review,marker):
        url=f"https://api.github.com/repos/{a.repository}/issues/{promotion.EVIDENCE_REVIEW_ISSUE_NUMBER}/comments"; api_request(url,a.token,method="POST",payload={"body":response}); posted=True
    print(json.dumps({"accepted":receipt["accepted"],"disposition":receipt["disposition"],"promoted_custodian_count":state["promoted_custodian_count"],"external_quorum_formed":state["verified_registry"]["external_quorum_formed"],"registry_hash":state["verified_registry"]["registry_hash"],"state_hash":state["state_hash"],"response_posted":posted,"external_success":False,"promotion":False,"agi":False,"asi":False},indent=2,sort_keys=True))

if __name__ == "__main__": main()
