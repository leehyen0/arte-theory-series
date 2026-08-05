# ARTE External Custodian Blind Challenge

This directory is a **public recruitment and verification surface** for an externally selected, commit–reveal evaluation of a frozen causal-authority classifier.

It is not an AGI/ASI claim, a deployment request, or a request to endorse the project. Classification alone cannot receive open-world transfer credit. A later typed specialist must produce a reversible patch and pass the original repository tests before any external success is recorded.

## Participate

No project-code contribution or endorsement is required. The first step is only a public role claim:

1. read the role boundaries below;
2. open [registration issue #3](https://github.com/leehyen0/arte-theory-series/issues/3);
3. post exactly one fenced JSON block using `REGISTRATION_TEMPLATE.json`;
4. do not post secrets, labels, nonces, private reveals, typed transformations or witness ledgers.

A valid registration comment is recorded only as `ACCEPTED_CLAIM_IDENTITY_UNVERIFIED`. Identity, affiliation and independence require separate verification.

## Required roles

Two different people are required:

1. `selector_labeler`
   - selects at least eight previously unused repository issues across at least five implementation-language families;
   - preserves issue, comment, source commit, path and blob custody;
   - creates typed causal witnesses and expected commitments privately;
   - keeps the selector secret and private reveal outside the predictor workspace.

2. `reveal_auditor`
   - receives the immutable selector reveal before prediction;
   - audits its hash and creates an HMAC commitment;
   - keeps the auditor secret outside the predictor workspace until the prediction seal exists.

An optional `timestamp_witness` may record the public challenge, audit commitment and prediction-seal hashes using another account or service.

## Registration

Open [**External custodians wanted for blind ARTE evaluation**](https://github.com/leehyen0/arte-theory-series/issues/3) and post exactly one fenced JSON block based on `REGISTRATION_TEMPLATE.json`.

Do not publish secrets, nonces, private reveals, expected labels, typed transformations or witness ledgers.

A syntactically valid comment is only an identity-unverified claim. It does not verify identity, affiliation or independence.

## Public workflow

```text
public registration claims
→ selector and auditor roles under different accounts
→ selector creates public challenge and private reveal
→ auditor commits to selector-reveal hash
→ public quorum seal
→ frozen prediction seal
→ selector and auditor reveal
→ standalone verification and score
```

## Files

- `REGISTRATION_TEMPLATE.json` — public registration claim template.
- `PREDICTIONS_TEMPLATE.json` — frozen-predictor output template.
- `PROTOCOL_FREEZES.json` — immutable protocol hashes and claim boundaries.
- `public_custodian_verifier.py` — dependency-free public hash/HMAC/ledger verifier.
- `test_public_custodian_verifier.py` — executable verifier self-tests.
- `CLAIM_BOUNDARY.md` — evidence and promotion limits.

## Verifier self-test

```bash
python -m pytest -q test_public_custodian_verifier.py
```

Current public state at mirror creation:

```text
external selector-labelers confirmed  0
external reveal auditors confirmed    0
external quorum formed                false
independent external successes        0
AGI / ASI                             false / false
```
