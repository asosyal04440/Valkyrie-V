# Warning Triage and Fix Plan

## Snapshot
- `cargo check` warnings: `49`
- `cargo clippy -D warnings` errors: `134`

## Top Categories
1. Unused imports/variables
2. Dead code / unreachable patterns
3. Formatting/consistency lints
4. `no_std`/panic-profile interaction in non-lib targets

## Triage Buckets
- **Fix now (Week-1):** obvious unused imports/vars, formatting diffs, literal grouping, trivial parens.
- **Fix next (Week-2):** dead code and architecture cleanup that may require refactor.
- **Waiver (time-bounded):** intentional experimental stubs; each waiver must include owner + expiry date.

## Execution Order
1. Run `cargo fmt --all` and commit formatting-only changes.
2. Remove unused imports/variables module-by-module.
3. Re-run clippy; resolve mechanical lint families.
4. Re-run full workspace tests/build.
5. Publish updated counts in `WARNING_BURNDOWN.md`.
