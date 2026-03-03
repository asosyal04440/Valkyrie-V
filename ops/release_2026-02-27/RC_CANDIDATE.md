# RC Candidate Cut and Rollback Notes

## Candidate
- Proposed tag: `v0.1.0-rc0`
- Candidate date: 2026-02-27
- Artifact snapshot:
  - `target/release/valkyrie_v.lib`
  - `target/release/libvalkyrie_v.rlib`

Evidence:
- `logs/release_artifacts.txt`
- `logs/release_dry_run.log`

## Cut Criteria (must be true)
- ABI smoke: pass
- no_std staticlib build: pass
- Workspace release build: pass (currently FAIL)
- Clippy/fmt gates: pass (currently FAIL)

## Rollback Plan
1. If RC validation fails, revert to previous known-good tag.
2. Re-run `cargo test --lib` and ABI smoke tests.
3. Re-publish corrected RC with incremented suffix (`rc1`, `rc2`, ...).
