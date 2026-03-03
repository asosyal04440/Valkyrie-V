# Owners and Blockers

## Owners
- Release Manager: `@release-owner`
- Build/Lint Owner: `@build-owner`
- ABI/GPU Owner: `@abi-owner`
- Security Owner: `@security-owner`
- QA/Perf Owner: `@qa-owner`

## Blockers (P0/P1)
1. **P0 (resolved)** Workspace test gate issue (`unwinding panics are not supported without std`) is mitigated by feature-gating no_std lib mode (`baremetal-lib`).
   - Evidence: `09_ws_test_after_panic_fix.txt` (`WS_TEST_EXIT=0`)
   - Owner: `@build-owner`
2. **P0 (resolved)** Previous Windows linker entrypoint error `LNK1561` for bin target is mitigated by gating bare-metal bin behind feature `baremetal-bin`.
   - Evidence: `Cargo.toml`, `07_ws_test_after_bin_gate.txt` (no `LNK1561` signature)
   - Owner: `@build-owner`
3. **P1 (active)** Clippy strict gate failing (`-D warnings`) with high error volume.
   - Evidence: `05_cargo_clippy.txt`
   - Owner: `@build-owner`
4. **P1 (active)** Formatting check failing in multiple files.
   - Evidence: `04_cargo_fmt_check.txt`
   - Owner: `@build-owner`

## Non-Blocker Notes
- Security advisory scan currently clean (`cargo audit --json`, vulnerabilities `0`).
