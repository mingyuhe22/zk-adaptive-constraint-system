//! Poseidon Merkle-path gadget.

use super::num::Num;
use acs::cs::{
    error::ConstructionError, formula::Formula, patch_array, Adapter, CircuitDriver, Field,
};
use std::rc::Rc;

/// Leaf that can be digested into a field formula.
pub trait MkTreeLeaf<F: Field, A: Adapter<F>> {
    /// Returns the leaf digest.
    fn digest(&mut self) -> Result<Formula<F, A>, ConstructionError>;
}
/// Merkle authentication path with a range-constrained leaf index.
pub struct MkPrf<F: Field, A: Adapter<F>, const TREE_HEIGHT: usize> {
    /// Little-endian path-direction bits encoded as an integer.
    pub idx: Num<F, A, TREE_HEIGHT>,
    /// Sibling digest at each level, from leaf to root.
    pub prf: [Formula<F, A>; TREE_HEIGHT],
}
impl<F: Field, A: Adapter<F>, const TREE_HEIGHT: usize> MkPrf<F, A, TREE_HEIGHT> {
    /// Allocates a Merkle authentication path.
    pub fn load(
        rc_circuit: &Rc<CircuitDriver<F, A>>,
        idx: Option<F>,
        prf: [Option<F>; TREE_HEIGHT],
    ) -> Result<Self, ConstructionError> {
        let idx = Num::load(rc_circuit, idx)?;
        let mut formulas = Vec::with_capacity(TREE_HEIGHT);
        for value in prf {
            formulas.push(Formula::load(value, rc_circuit)?);
        }
        let prf = formulas
            .try_into()
            .map_err(|_| ConstructionError::InvalidArrayLength)?;
        Ok(Self { idx, prf })
    }
    /// Computes the root selected by the index bits and sibling path.
    pub fn calc_root<Leaf: MkTreeLeaf<F, A>>(
        &mut self,
        mut leaf: Leaf,
    ) -> Result<Formula<F, A>, ConstructionError> {
        let mut root = leaf.digest()?;
        for i in 0..TREE_HEIGHT {
            let bit = self
                .idx
                .bit_mut(i)
                .ok_or(ConstructionError::InvalidArrayLength)?;
            let l = bit.cond_pick(self.prf[i].dupl()?, root.dupl()?)?;
            let r = bit.cond_pick(root.dupl()?, self.prf[i].dupl()?)?;
            [root] = patch_array("Poseidon", vec![F::from_str("2")?], vec![l, r])?;
        }
        Ok(root)
    }
}
