# Evidence Policy

## Evidence tiers

- **Tier 0: Conceptual framing**
  - definitions,
  - diagrams,
  - theory maps,
  - proof sketches,
  - proposed experiments.

- **Tier 1: Reproducible toy demo**
  - public code,
  - fixed seeds,
  - clear environment,
  - raw toy outputs included.

- **Tier 2: Public benchmark run**
  - public benchmark,
  - released code,
  - released config,
  - released raw outputs,
  - repeatable command.

- **Tier 3: Independent external reproduction**
  - someone outside the author reproduces the claim,
  - independent environment,
  - public reproduction notes.

- **Tier 4: Multi-run, cross-model, externally replicated evidence**
  - multiple independent runs,
  - multiple models or tasks,
  - documented failure cases,
  - statistical summary.

## Current public status

This index repository is **Tier 0**.

Individual repositories may contain toy experiment scaffolds. A scaffold is not a validated experimental result unless it includes reproducible public results, seeds, and raw outputs.

## Public release rule

For v0.1, README files and paper drafts should claim only conceptual framing and proposed/toy-level demonstrations.

Do not describe internal traces, private logs, local controller outputs, or development artifacts as public proof.

## Required wording for internal evidence

Use:

> Internal traces informed development and design.

Do not use:

> Internal traces prove the theory.

## Required wording for toy experiments

Use:

> This toy experiment illustrates a possible mechanism.

Do not use:

> This validates the theory.
