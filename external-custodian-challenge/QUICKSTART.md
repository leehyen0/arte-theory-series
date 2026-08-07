# External Custodian Quickstart

This is the shortest path for an external volunteer.

## 1. Register on issue #3

```bash
python external-custodian-challenge/preflight_external_custodian.py registration --example > registration.json
python external-custodian-challenge/preflight_external_custodian.py registration registration.json
```

Edit the example first. If `local_preflight_pass` is `true`, post the JSON to issue #3 as exactly one fenced `json` block.

Local preflight never grants authority. GitHub still checks the real comment author, owner/bot status, duplicate login, and live protocol state.

## 2. Evidence review on issue #10

After issue #3 returns an accepted identity-unverified receipt:

```bash
python external-custodian-challenge/preflight_external_custodian.py evidence --example > evidence.json
python external-custodian-challenge/preflight_external_custodian.py evidence evidence.json
```

Required evidence categories:

```text
github_account_control
non_github_identity_anchor
evaluation_independence
```

A separate reviewer can preflight an attestation with:

```bash
python external-custodian-challenge/preflight_external_custodian.py review --example > review.json
python external-custodian-challenge/preflight_external_custodian.py review review.json
```

Do not publish government IDs, home addresses, phone numbers, private email addresses, secrets, nonces, private reveals, labels, witnesses, or private task material.

## 3. Commit–reveal on issue #8

Only after a live evidence-reviewed two-role quorum exists:

```bash
python external-custodian-challenge/preflight_external_custodian.py event --example > event.json
python external-custodian-challenge/preflight_external_custodian.py event event.json
```

The server still enforces live quorum, actor role, event order, and cross-event hash references.

## Meaning of local PASS

It means only that local JSON shape, frozen hashes, obvious SHA-256 fields, required local attestations, and obvious sensitive-field exclusions passed.

It does not mean identity verified, independence verified, external quorum, independent evaluation, external success, promotion, AGI, or ASI.

## Public path

```text
issue #3 registration
→ issue #10 evidence/reviewer ledger
→ live evidence-reviewed registry
→ issue #8 commit–reveal ledger
→ standalone public verifier
```
