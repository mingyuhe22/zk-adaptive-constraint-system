//! Adaptive constraint-system primitives for building a circuit once and
//! replaying it against witness generators and proof-system adapters.
//!
//! The central invariant is that witness and constraint passes must allocate
//! identical signals, public inputs, and constraints. Use
//! [`cs::CircuitDriver::ensure_same_shape`] whenever the passes are run
//! separately.
#![warn(missing_docs)]

/// Circuit construction, formula, witness, and adapter abstractions.
pub mod cs;
/// Field implementations supported by the core crate.
pub mod field;

#[cfg(test)]
mod test;
