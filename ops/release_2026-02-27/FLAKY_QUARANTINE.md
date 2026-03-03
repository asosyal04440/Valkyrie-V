# Test Stability / Flaky Quarantine

## Current State
- Deterministic failures observed are **build/link** related, not flaky runtime assertions.
- ABI v2 smoke tests pass reliably in repeated local runs.

## Quarantine Policy
- A test is marked flaky only if it fails intermittently across >=3 reruns on same commit.
- Quarantined tests must include:
  - Owner
  - Failure signature
  - Repro notes
  - Removal deadline

## Current Quarantine List
- None (0)

## Stability Command Set
- `cargo test --lib tests::abi_version_is_nonzero -- --exact`
- `cargo test --lib tests::submit_batch_and_flush_fence_completion_poll -- --exact`
- `cargo test --lib tests::submit_batch_unaligned_pointer_is_safe -- --exact`
