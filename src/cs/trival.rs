//! Driver alias for witness-only or shape-only construction.

use super::{error::ConstructionError, Adapter, CircuitDriver, Constraint, Field};

impl<F: Field> Adapter<F> for () {
    fn do_constraint(&mut self, _: Constraint<F>) -> Result<(), ConstructionError> {
        Err(ConstructionError::AdapterError)
    }
}
/// Circuit driver that intentionally has no constraint adapter.
pub type TrivalCircuitDriver<F> = CircuitDriver<F, ()>;
