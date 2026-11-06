//! Example Poseidon Merkle-path circuit.

use std::rc::Rc;

use acs::cs::{
    error::ConstructionError, formula::Formula, patch_array, Adapter, CircuitDriver, Field,
};
use serde::Deserialize;

use self::gadgets::mkt::MkTreeLeaf;

/// Boolean, integer, and Merkle-path gadgets.
pub mod gadgets;

struct MkLeaf<F: Field, A: Adapter<F>> {
    nonce: Formula<F, A>,
}
impl<F: Field, A: Adapter<F>> MkLeaf<F, A> {
    fn load(
        rc_circuit: &Rc<CircuitDriver<F, A>>,
        nonce: Option<F>,
    ) -> Result<Self, ConstructionError> {
        Ok(Self {
            nonce: Formula::load(nonce, rc_circuit)?,
        })
    }
}
impl<F: Field, A: Adapter<F>> MkTreeLeaf<F, A> for MkLeaf<F, A> {
    fn digest(&mut self) -> Result<Formula<F, A>, ConstructionError> {
        let [digest] = patch_array(
            "Poseidon",
            vec![F::from_str("2")?],
            vec![self.nonce.dupl()?, self.nonce.dupl()?],
        )?;
        Ok(digest)
    }
}

/// Three-level Merkle membership assignment with a public expected root.
#[derive(Clone, Deserialize)]
pub struct MainCircuit<F: Field> {
    nonce: Option<F>,
    idx: Option<F>,
    prf: [Option<F>; 3],
    root: Option<F>,
}
impl<F: Field> MainCircuit<F> {
    /// Creates a Merkle-path circuit assignment.
    pub fn new(nonce: Option<F>, idx: Option<F>, prf: [Option<F>; 3], root: Option<F>) -> Self {
        Self {
            nonce,
            idx,
            prf,
            root,
        }
    }

    /// Allocates this assignment and emits its constraints.
    pub fn instantiate<A: Adapter<F>>(
        &self,
        rc_circuit: &Rc<CircuitDriver<F, A>>,
    ) -> Result<(), ConstructionError> {
        let mut mk_prf = gadgets::mkt::MkPrf::<F, A, 3>::load(rc_circuit, self.idx, self.prf)?;
        let mk_leaf = MkLeaf::load(rc_circuit, self.nonce)?;
        let expected_root = Formula::load(self.root, rc_circuit)?.to_input()?;
        mk_prf.calc_root(mk_leaf)?.eq_to(expected_root)?;
        Ok(())
    }
}
