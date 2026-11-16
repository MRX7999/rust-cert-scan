## Summary

Which plan task this closes, or why it is outside the plan.

## Checks

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo test --workspace --locked`

Authorized use only. Tests and fixtures stay on `127.0.0.1` or the stand compose network.
