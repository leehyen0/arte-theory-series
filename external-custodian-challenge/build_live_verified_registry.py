from __future__ import annotations
from pathlib import Path
import argparse
import json
import os

import process_identity_independence_review as proc


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    p.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    p.add_argument("--registration-comments-json")
    p.add_argument("--review-comments-json")
    p.add_argument("--output", required=True)
    p.add_argument("--state-output")
    a = p.parse_args()

    raw_reg = json.loads(Path(a.registration_comments_json).read_text()) if a.registration_comments_json else proc.fetch_issue_comments(a.repository, 3, a.token)
    raw_review = json.loads(Path(a.review_comments_json).read_text()) if a.review_comments_json else proc.fetch_issue_comments(a.repository, 10, a.token)
    _, state = proc.rebuild_state(raw_registration_comments=raw_reg, raw_review_comments=raw_review)
    Path(a.output).write_text(json.dumps(state["verified_registry"], indent=2, sort_keys=True) + "\n")
    if a.state_output:
        Path(a.state_output).write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "registry_hash": state["verified_registry"]["registry_hash"],
        "promoted_custodian_count": state["promoted_custodian_count"],
        "external_quorum_formed": state["verified_registry"]["external_quorum_formed"],
        "absolute_human_uniqueness_proven": False,
        "absolute_independence_proven": False,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
