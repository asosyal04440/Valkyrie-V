# Release Evidence Bundle (2026-02-27)

This folder contains a complete execution bundle for the 14-item gate request.

## Start Here
- `TRACKER.md` — unified status board
- `FINAL_GO_NO_GO.md` — final decision record
- `OWNERS_BLOCKERS.md` — owners and blocker list

## Evidence Logs
- Baseline: `01_cargo_check.txt`, `02_cargo_test.txt`, `03_cargo_build_release.txt`, `04_cargo_fmt_check.txt`, `05_cargo_clippy.txt`
- Security: `06_cargo_audit.json`
- Dry run: `logs/release_dry_run.log`
- Soak: `logs/soak_run.log`
- Matrix: `logs/matrix_rerun.log`
