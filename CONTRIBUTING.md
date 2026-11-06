# Contributing

Changes to circuit code must preserve the invariants documented in the main
README. In particular:

- never branch circuit structure on witness values;
- use fixed-arity `patch_array` calls;
- constrain every signal allocated from `FormulaRepr`;
- mark verifier-visible statements with `Formula::to_input`;
- test both honest and adversarial assignments;
- add a Bellman satisfaction test for adapter-visible behavior.

Run the core checks from the repository root:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
RUSTDOCFLAGS="-D missing_docs" cargo doc --locked --no-deps
```

Run the same commands inside `acs-sample` with the pinned
`nightly-2024-08-01` toolchain. Keep soundness fixes and refactors in separate,
reviewable commits when possible. Pull requests that alter a constraint must
explain the intended algebraic relation and why the tests detect an
under-constrained witness.
