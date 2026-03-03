# Operator Runbook (RC-prep)

## Startup Validation
1. Validate ABI level: `valkyrie_abi_version() >= 2`
2. Initialize framebuffer: `valkyrie_framebuffer_init(...)`
3. Submit GPU batch: `valkyrie_gpu_submit_batch(...)`
4. Flush + poll completion: `valkyrie_gpu_flush()` and `valkyrie_gpu_completion_poll(...)`

## Daily Validation Commands
- `cargo build --lib`
- `cargo test --lib`
- `cargo test --lib tests::submit_batch_and_flush_fence_completion_poll -- --exact`

## Failure Handling
- Build failure with `LNK1561`: verify bin entrypoint strategy before production tag.
- Clippy/fmt failures: treat as gate blockers unless temporary waiver approved.

## Logs of Interest
- `ops/release_2026-02-27/logs/release_dry_run.log`
- `ops/release_2026-02-27/logs/soak_run.log`
- `ops/release_2026-02-27/logs/matrix_rerun.log`
