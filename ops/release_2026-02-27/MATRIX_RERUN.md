# Full Matrix Rerun Report

## Local Repro Matrix (2026-02-27)
- `x86_64-pc-windows-msvc`: PASS (`check_exit=0`)
- `x86_64-pc-windows-gnu`: PASS (`check_exit=0`)
- `x86_64-unknown-linux-gnu`: PASS (`check_exit=0`)
- `aarch64-unknown-linux-gnu`: FAIL (`check_exit=101`)

Evidence:
- `logs/matrix_rerun.log`
- `logs/matrix_check_*.txt`
- `logs/matrix_target_add_*.txt`

## CI Green Status
- GitHub Actions full green run cannot be proven from local workspace alone.
- Required follow-up: execute workflow on GitHub and attach run URL(s).

## Interim Decision
- Matrix gate is **not fully green** due local ARM64 failure and missing remote CI proof.
