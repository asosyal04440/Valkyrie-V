# Contributing to Valkyrie-V

Thanks for contributing.

## Development setup

1. Install stable Rust toolchain.
2. Clone this repository.
3. Ensure internet access for pulling `ironshim-rs` git dependency.
4. Run checks before opening a PR:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

## Pull request expectations

- Keep changes scoped and minimal.
- Include tests for new behavior when practical.
- Document any new `unsafe` usage with `// SAFETY:` rationale.
- Update `README.md` or `SECURITY.md` when behavior/policy changes.

## Reporting issues

Please include:

- Platform and Rust version
- Reproduction steps
- Expected vs actual behavior
- Logs or traces if available
