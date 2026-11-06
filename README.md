# Adaptive Constraint System

ACS is a small Rust frontend for constructing a circuit once and replaying the
same structure in two modes:

- a witness pass calculates every allocated signal;
- a constraint pass translates the same formulas through an `Adapter`.

`Formula` is intentionally move-only. Reusing a complex expression through
`Formula::dupl` materializes it once as a signal and emits the equality
constraint needed to preserve its meaning.

## Safety invariants

Circuit code and adapters must preserve these invariants:

1. Circuit shape must not depend on witness values. Integrations must build a
   canonical assignment-free shape pass and use `ensure_same_shape` to compare
   both witness and constraint passes against it.
2. Public statements must use `Formula::to_input`. Adapters must allocate the
   recorded signal indices as native public inputs, not private witnesses.
3. Derived witnesses created with `Formula::alloc` are unconstrained until the
   gadget explicitly relates them to existing formulas.
4. Adapter patches use `patch_array`, whose const-generic output arity prevents
   witness-dependent output allocation.
5. Integer decomposition is valid only up to `Field::CAPACITY_BITS`. Gadgets
   must reject wider ranges because binary representation is no longer
   injective in the field.

The crates forbid `unsafe`. This repository has not received an independent
cryptographic audit and should not be treated as audited proof-system code.

## Formula representations

`FormulaRepr` supports witness-side integer operations that are not circuit
field operations, such as shifts and bit extraction. These operations compute
assignments only. Allocating the result does not automatically add a
constraint; the gadget remains responsible for boolean, range, and relation
constraints.

## Adapter patches

Patches connect ACS to backend-native gadgets such as Poseidon. A patch has a
string key, constant parameters, fixed input signals, and a compile-time output
count. Both the native witness script and the constraint adapter must implement
identical semantics and reject unsupported keys, parameters, and arities.

The Bellman integration and a public-root Merkle example live under
[`acs-sample`](./acs-sample/README.md).

## Development

The core crate has an MSRV of Rust 1.82 and pins Rust 1.85.1 for development:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
RUSTDOCFLAGS="-D missing_docs" cargo doc --locked --no-deps
```

Field strings are canonical decimal values by default and hexadecimal values
when prefixed with `0x`.

The sample is isolated on `nightly-2024-08-01` because of its pinned legacy
Bellman dependencies. Entering `acs-sample` selects that toolchain.
