# PROD_READY_GATE — Valkyrie-V

## Goal
Ship a production-ready release candidate in 2 weeks with measurable quality gates and a strict go/no-go decision.

## Scope
- In scope: build/test health, ABI v2 stability, no_std staticlib viability, CI reliability, warning debt control, release hygiene.
- Out of scope: new feature development not required for release readiness.

## 2-Week Timeline
| Day | Focus | Required Output |
|---|---|---|
| 1 | Baseline and ownership | Baseline metrics, owners, blocker list |
| 2 | Build/lint cleanup | Warning triage and fix plan |
| 3 | Test stability | Flaky tests removed or quarantined with owner |
| 4 | ABI v2 contract checks | Completion poll flow CI smoke added |
| 5 | Mid-gate review | Week-1 pass/fail decision |
| 6 | Warning debt burn-down | Net warning count down or approved waivers |
| 7 | Security baseline | Audit report and decision log |
| 8 | Release dry-run | Clean checkout release build artifacts |
| 9 | Stress/soak prep | Stress plan and scripts pinned |
| 10 | Soak run | Long-run logs + triage |
| 11 | Full matrix rerun | Reproducible CI green run |
| 12 | Docs/release notes | Operator-facing docs finalized |
| 13 | RC candidate cut | RC artifacts + rollback notes |
| 14 | Final go/no-go | Signed decision record |

## Exit Criteria (All Must Pass)
1. `cargo build --workspace --all-targets` exits 0.
2. `cargo test --workspace --all-targets` exits 0 with no flaky rerun.
3. `cargo build --release` succeeds from clean checkout.
4. no_std staticlib path remains valid (`crate-type` and lib build verified).
5. ABI v2 completion flow smoke test passes in CI.
6. `cargo fmt --all -- --check` passes.
7. `cargo clippy --workspace --all-targets -- -D warnings` passes or has approved, time-bounded waiver list.
8. Required CI checks are green for 3 consecutive days.
9. Security audit has no unapproved high/critical findings.
10. Open P0/P1 blockers = 0 at go/no-go.

## Daily Command Checklist
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo build --release
```

## Daily Review Rules
- Warning count must not increase day-over-day unless explicitly approved.
- Any required CI red state older than 24h is an escalation.
- ABI v2 smoke must run at least once per day on latest head.

## Risks and Escalation
- Warning debt hides regressions → escalate if warning count grows 2 days in a row.
- CI matrix drift (especially non-primary targets) → escalate on repeated failures.
- ABI/API drift → escalate on any contract test failure.
- Release reproducibility issues → escalate if clean-room build diverges.

## Definition of Done
- All 10 exit criteria pass with attached evidence.
- RC build is reproducible from clean checkout.
- Rollback steps are tested and documented.
- Go/no-go approved by engineering owner.
