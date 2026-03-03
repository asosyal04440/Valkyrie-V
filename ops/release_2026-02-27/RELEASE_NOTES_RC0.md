# Release Notes (RC0 Draft)

## Highlights
- ABI v2 non-blocking completion poll path available.
- `staticlib + rlib` outputs enabled for kernel-side linking.
- C header published: `include/valkyrie_v.h`.
- echOS sample bridge added: `examples/echos/valkyrie_bridge.c`.
- CI includes dedicated ABI v2 smoke checks.

## Known Limitations
- Workspace-wide release build currently fails on bin target entrypoint (`LNK1561`).
- Strict clippy/fmt gates are not yet green.
- Full matrix reproducibility not fully proven.

## Suggested Tagging
- Use `v0.1.0-rc0` or `beta` tag, not `stable`.
