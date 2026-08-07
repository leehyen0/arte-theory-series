from __future__ import annotations
from pathlib import Path
from typing import Any
import argparse, json, os, urllib.request
import external_custodian_event_state as sm

RECEIPT_MARKER = "<!-- arte-custodian-event-receipt:"


def api_request(url: str, token: str, *, method: str = "GET", payload: Any = None) -> Any:
    data = None
    headers = {"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"arte-custodian-event-state"}
    if token: headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        data = json.dumps(payload).encode(); headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as response:
        body = response.read(); return json.loads(body) if body else None


def fetch_issue_comments(repository: str, issue_number: int, token: str) -> list[dict[str, Any]]:
    out=[]; page=1
    while True:
        url=f"https://api.github.com/repos/{repository}/issues/{issue_number}/comments?per_page=100&page={page}"
        batch=api_request(url,token)
        if not isinstance(batch,list): raise RuntimeError("GitHub comments response is not a list")
        out.extend(batch)
        if len(batch)<100: break
        page+=1
    return out


def normalize_comment(raw: dict[str, Any]) -> dict[str, Any]:
    user=raw.get("user") or {}
    return {"id":int(raw.get("id",0)),"body":str(raw.get("body","")),"author_login":str(user.get("login","")),"author_type":str(user.get("type","")),"created_at":str(raw.get("created_at","")),"html_url":str(raw.get("html_url",""))}


def event_comments(raw_comments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows=[]
    for raw in raw_comments:
        login=str((raw.get("user") or {}).get("login",""))
        body=str(raw.get("body",""))
        if login.endswith("[bot]") or RECEIPT_MARKER in body: continue
        rows.append(normalize_comment(raw))
    return rows


def render_response(receipt: dict[str, Any], state: dict[str, Any]) -> str:
    problems = receipt.get("problems", [])
    lines=["### ARTE Custodian event receipt","",f"- accepted: `{str(receipt.get('accepted',False)).lower()}`",f"- disposition: `{receipt.get('disposition')}`",f"- phase after rebuild: `{state.get('phase')}`",f"- verified external quorum: `{str(state.get('verified_external_quorum',False)).lower()}`",f"- state hash: `{state.get('state_hash')}`",f"- receipt hash: `{receipt.get('receipt_hash')}`"]
    if problems:
        lines += ["","Problems:",*([f"- `{x}`" for x in problems])]
    lines += ["","```text","independent evaluation  false","external success        false","patch authority          false","promotion                false","AGI / ASI                false / false","```"]
    return "\n".join(lines)+"\n"


def process(*, event: dict[str, Any], raw_comments: list[dict[str, Any]], registry: dict[str, Any], predictor_login: str) -> tuple[dict[str, Any],dict[str, Any],str]:
    issue=event.get("issue") or {}; current=event.get("comment") or {}
    if int(issue.get("number",0)) != sm.EVENT_LEDGER_ISSUE_NUMBER: raise ValueError("WRONG_EVENT_LEDGER_ISSUE")
    cid=int(current.get("id",0))
    if not any(int(x.get("id",0))==cid for x in raw_comments): raw_comments=[*raw_comments,current]
    state=sm.build_state(registry=registry,comments=event_comments(raw_comments),predictor_login=predictor_login)
    matches=[r for r in state["receipts"] if int(r.get("source_comment_id",0))==cid]
    if len(matches)!=1: raise RuntimeError("TARGET_EVENT_RECEIPT_NOT_UNIQUE")
    receipt=matches[0]; markdown=render_response(receipt,state)
    return receipt,state,markdown


def already_posted(raw_comments: list[dict[str, Any]], marker: str) -> bool:
    return any(marker in str(x.get("body","")) for x in raw_comments)


def main() -> None:
    p=argparse.ArgumentParser(); p.add_argument("--event",required=True); p.add_argument("--repository",default=os.environ.get("GITHUB_REPOSITORY","")); p.add_argument("--token",default=os.environ.get("GITHUB_TOKEN","")); p.add_argument("--comments-json"); p.add_argument("--registry",required=True); p.add_argument("--output-dir",required=True); p.add_argument("--predictor-login",default="leehyen0"); p.add_argument("--post-response",action="store_true"); a=p.parse_args()
    event=json.loads(Path(a.event).read_text()); issue_number=int((event.get("issue") or {}).get("number",0)); cid=int((event.get("comment") or {}).get("id",0))
    if a.comments_json: raw_comments=json.loads(Path(a.comments_json).read_text())
    else:
        if not a.repository or not a.token: raise RuntimeError("repository and token required without --comments-json")
        raw_comments=fetch_issue_comments(a.repository,issue_number,a.token)
    registry=json.loads(Path(a.registry).read_text())
    receipt,state,markdown=process(event=event,raw_comments=raw_comments,registry=registry,predictor_login=a.predictor_login)
    marker=f"{RECEIPT_MARKER}{cid}:{receipt['receipt_hash']} -->"; response=marker+"\n"+markdown
    out=Path(a.output_dir); out.mkdir(parents=True,exist_ok=True)
    (out/"event_receipt.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    (out/"event_state.json").write_text(json.dumps(state,indent=2,sort_keys=True)+"\n")
    (out/"event_response.md").write_text(response)
    posted=False
    if a.post_response and not already_posted(raw_comments,marker):
        url=f"https://api.github.com/repos/{a.repository}/issues/{issue_number}/comments"; api_request(url,a.token,method="POST",payload={"body":response}); posted=True
    print(json.dumps({"accepted":receipt["accepted"],"disposition":receipt["disposition"],"phase":state["phase"],"state_hash":state["state_hash"],"receipt_hash":receipt["receipt_hash"],"response_posted":posted,"external_success":False,"promotion":False,"agi":False,"asi":False},indent=2,sort_keys=True))

if __name__ == "__main__": main()
