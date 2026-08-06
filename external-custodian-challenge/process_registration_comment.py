from __future__ import annotations

from pathlib import Path
from typing import Any
import argparse
import json
import os
import urllib.request

import public_registration_intake as intake


def api_request(url: str, token: str, *, method: str = "GET", payload: Any = None) -> Any:
    data = None
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "arte-public-registration-intake",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read()
        return json.loads(body) if body else None


def normalize_comment(raw: dict[str, Any], issue_number: int) -> dict[str, Any]:
    user = raw.get("user") or {}
    return {
        "id": int(raw.get("id", 0)),
        "body": str(raw.get("body", "")),
        "author_login": str(user.get("login", "")),
        "author_type": str(user.get("type", "")),
        "html_url": str(raw.get("html_url", "")),
        "created_at": str(raw.get("created_at", "")),
        "issue_number": int(issue_number),
    }


def fetch_issue_comments(repository: str, issue_number: int, token: str) -> list[dict[str, Any]]:
    comments: list[dict[str, Any]] = []
    page = 1
    while True:
        url = (
            f"https://api.github.com/repos/{repository}/issues/{issue_number}/comments"
            f"?per_page=100&page={page}"
        )
        batch = api_request(url, token)
        if not isinstance(batch, list):
            raise RuntimeError("GitHub comments response is not a list")
        comments.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return comments


def response_with_marker(markdown: str, comment_id: int, receipt_hash: str) -> str:
    return f"<!-- arte-registration-intake:{comment_id}:{receipt_hash} -->\n" + markdown


def already_posted(raw_comments: list[dict[str, Any]], marker: str) -> bool:
    return any(marker in str(row.get("body", "")) for row in raw_comments)


def process(
    *,
    event: dict[str, Any],
    raw_comments: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], str]:
    issue = event.get("issue") or {}
    event_comment = event.get("comment") or {}
    issue_number = int(issue.get("number", 0))

    if issue_number != intake.REGISTRATION_ISSUE_NUMBER:
        raise ValueError("WRONG_REGISTRATION_ISSUE_EVENT")

    comment_id = int(event_comment.get("id", 0))
    if not any(int(row.get("id", 0)) == comment_id for row in raw_comments):
        raw_comments = [*raw_comments, event_comment]

    normalized = [normalize_comment(row, issue_number) for row in raw_comments]
    registry = intake.build_registry(normalized)
    matches = [
        receipt
        for receipt in registry["receipts"]
        if int(receipt.get("source_comment_id", 0)) == comment_id
    ]
    if len(matches) != 1:
        raise RuntimeError("TARGET_COMMENT_RECEIPT_NOT_UNIQUE")

    receipt = matches[0]
    markdown = intake.render_receipt_markdown(receipt, registry)
    return receipt, registry, markdown


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    parser.add_argument("--comments-json")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--post-response", action="store_true")
    args = parser.parse_args()

    event = json.loads(Path(args.event).read_text())
    issue_number = int((event.get("issue") or {}).get("number", 0))
    comment_id = int((event.get("comment") or {}).get("id", 0))

    if args.comments_json:
        raw_comments = json.loads(Path(args.comments_json).read_text())
    else:
        if not args.repository or not args.token:
            raise RuntimeError("repository and token are required without --comments-json")
        raw_comments = fetch_issue_comments(args.repository, issue_number, args.token)

    receipt, registry, markdown = process(event=event, raw_comments=raw_comments)
    response = response_with_marker(markdown, comment_id, receipt["receipt_hash"])

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "registration_receipt.json").write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
    (output_dir / "registration_registry.json").write_text(
        json.dumps(registry, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
    (output_dir / "registration_response.md").write_text(response)

    posted = False
    marker = f"<!-- arte-registration-intake:{comment_id}:{receipt['receipt_hash']} -->"
    if args.post_response and not already_posted(raw_comments, marker):
        url = f"https://api.github.com/repos/{args.repository}/issues/{issue_number}/comments"
        api_request(url, args.token, method="POST", payload={"body": response})
        posted = True

    print(json.dumps({
        "accepted": receipt["accepted"],
        "disposition": receipt["disposition"],
        "receipt_hash": receipt["receipt_hash"],
        "registry_hash": registry["registry_hash"],
        "accepted_claim_count": registry["accepted_claim_count"],
        "syntactic_two_role_candidate": registry["syntactic_two_role_candidate"],
        "external_quorum_formed": registry["external_quorum_formed"],
        "response_posted": posted,
        "promotion": False,
        "agi": False,
        "asi": False,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
