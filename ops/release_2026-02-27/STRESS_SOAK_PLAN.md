# Stress / Soak Plan

## Goal
Validate ABI v2 completion path stability under repeated execution and capture triage artifacts.

## Scripts
- `scripts/soak_run.ps1` (iterative soak)
- `scripts/release_dry_run.ps1` (clean/build/artifact capture)

## Baseline Soak Scenario
- Iterations: `25`
- Test: `tests::submit_batch_and_flush_fence_completion_poll`
- Pass condition: all iterations pass, no panic, no non-zero exit code.

## Triage Inputs
- `logs/soak_run.log`
- `logs/soak_iter_*.txt`

## Escalation Rule
- Any non-zero exit code -> immediate blocker and owner assignment.
