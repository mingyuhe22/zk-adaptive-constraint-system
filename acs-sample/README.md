# ACS Bellman sample

This crate demonstrates an ACS adapter for Bellman PLONK and a three-level
Poseidon Merkle-membership circuit.

The circuit contains:

- constrained booleans with checked logical combinators;
- range-constrained integers with exhaustive unsigned and two's-complement
  comparison tests;
- fixed-arity Poseidon patches;
- a Merkle root marked as a native Bellman public input.

`synthesize_circuit` first builds an assignment-free reference shape, then
verifies that both the witness and constraint passes match it. It allocates the
recorded public signal indices with Bellman's `alloc_input` and translates every
recorded constraint. The test suite also checks Bellman satisfaction, the
public root value, and rejection of an incorrect root.

## Build and test

Legacy Bellman dependencies require the pinned `nightly-2024-08-01` toolchain:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
RUSTDOCFLAGS="-D missing_docs" cargo doc --locked --no-deps
```

## Run

The binary accepts a circuit input JSON path:

```bash
cargo run -- path/to/input.json
```

The JSON object must contain `nonce`, `idx`, a three-element `prf`, and the
expected public `root`. Values are canonical decimal strings or hexadecimal
strings prefixed with `0x`. `idx` must fit in three bits, and `root` must match
the Poseidon Merkle calculation.

The binary synthesizes a testing assembly, checks that its constraints are
satisfied, and finalizes it. It is an adapter example, not a proving CLI.
