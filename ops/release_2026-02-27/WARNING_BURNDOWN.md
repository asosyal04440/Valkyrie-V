# Warning Debt Burn-Down

## Baseline (2026-02-27)
- `cargo check` warnings: `49`
- `cargo clippy -D warnings` errors: `134`
- `cargo fmt --check` diffs: `536`

## Current Snapshot (cleanup wave 1)
- `cargo clippy -D warnings` errors: `117`
- Evidence: `10_clippy_after_lowrisk_cleanup.txt`

## Burn-Down Target
- Day 5: `clippy errors < 80`
- Day 8: `clippy errors < 30`
- Day 10: `clippy errors = 0` or approved waivers only
- Day 10: `fmt diffs = 0`

## Waiver Template
- Issue ID:
- Owner:
- Reason:
- Expiry date:
- Replacement/fix plan:
