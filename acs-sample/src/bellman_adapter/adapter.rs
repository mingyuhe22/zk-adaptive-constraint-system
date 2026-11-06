use acs::cs::{error::ConstructionError, Adapter, Constraint, Elem, Operator};
use franklin_crypto::{
    bellman::{pairing::*, plonk::better_better_cs::cs::*},
    plonk::circuit::allocated_num::Num,
};
use rescue_poseidon::{CircuitGenericSponge, PoseidonParams};

use super::{convert_field, BellmanField};

/// Converts ACS constraints into Bellman PLONK constraints.
pub struct BellmanAdapter<'a, E: Engine, CS: ConstraintSystem<E>> {
    cs: &'a mut CS,
    vars: Vec<Num<E>>,
}
impl<'a, E: Engine, CS: ConstraintSystem<E>> BellmanAdapter<'a, E, CS> {
    /// Creates an adapter over the Bellman variables indexed by ACS signal id.
    pub fn new(cs: &'a mut CS, vars: Vec<Num<E>>) -> Self {
        Self { cs, vars }
    }
}
impl<'a, E: Engine, CS: ConstraintSystem<E>, F: BellmanField<E>> Adapter<F>
    for BellmanAdapter<'a, E, CS>
{
    fn do_constraint(&mut self, constraint: Constraint<F>) -> Result<(), ConstructionError> {
        match constraint {
            Constraint::Expr(expr) => {
                let tmp = expr_to_var(self.cs, &self.vars, &expr)?;
                tmp.enforce_equal(self.cs, &Num::zero())
                    .map_err(|_| ConstructionError::AdapterError)?;
            }
            Constraint::Patch(patch) => match patch.key.as_str() {
                "Poseidon" => {
                    let [param] = patch.params.as_slice() else {
                        return Err(ConstructionError::UnsupportedPatch);
                    };
                    if *param != F::from_str("2")? {
                        return Err(ConstructionError::UnsupportedPatch);
                    }
                    let [left_idx, right_idx, output_idx] = patch.indexes.as_slice() else {
                        return Err(ConstructionError::UnsupportedPatch);
                    };
                    let left = self
                        .vars
                        .get(*left_idx)
                        .cloned()
                        .ok_or(ConstructionError::SignalIndexOutOfBounds)?;
                    let right = self
                        .vars
                        .get(*right_idx)
                        .cloned()
                        .ok_or(ConstructionError::SignalIndexOutOfBounds)?;
                    let output = self
                        .vars
                        .get(*output_idx)
                        .ok_or(ConstructionError::SignalIndexOutOfBounds)?;

                    const RATE: usize = 2;
                    const WIDTH: usize = 3;
                    let poseidon_params = PoseidonParams::<E, RATE, WIDTH>::default();
                    let hash =
                        CircuitGenericSponge::hash(self.cs, &[left, right], &poseidon_params, None)
                            .map_err(|_| ConstructionError::AdapterError)?;
                    let result = hash
                        .first()
                        .ok_or(ConstructionError::AdapterError)?
                        .clone()
                        .into_num(self.cs)
                        .map_err(|_| ConstructionError::AdapterError)?;
                    result
                        .enforce_equal(self.cs, output)
                        .map_err(|_| ConstructionError::AdapterError)?;
                }
                _ => return Err(ConstructionError::UnsupportedPatch),
            },
        }
        Ok(())
    }
}
fn expr_to_var<E: Engine, CS: ConstraintSystem<E>, F: BellmanField<E>>(
    cs: &mut CS,
    vars: &[Num<E>],
    expr: &[Elem<F>],
) -> Result<Num<E>, ConstructionError> {
    let mut stack = Vec::with_capacity(expr.len());
    for elem in expr.iter().rev().copied() {
        match elem {
            Elem::Idx(index) => stack.push(
                vars.get(index)
                    .cloned()
                    .ok_or(ConstructionError::SignalIndexOutOfBounds)?,
            ),
            Elem::Constant(value) => {
                stack.push(Num::Constant(convert_field::<E, F>(value)?));
            }
            Elem::Operator(operator) => {
                let left = stack.pop().ok_or(ConstructionError::MalformedExpression)?;
                let right = stack.pop().ok_or(ConstructionError::MalformedExpression)?;
                let result = match operator {
                    Operator::Add => left
                        .add(cs, &right)
                        .map_err(|_| ConstructionError::AdapterError)?,
                    Operator::Mul => left
                        .mul(cs, &right)
                        .map_err(|_| ConstructionError::AdapterError)?,
                };
                stack.push(result);
            }
        }
    }
    if stack.len() != 1 {
        return Err(ConstructionError::MalformedExpression);
    }
    stack.pop().ok_or(ConstructionError::MalformedExpression)
}
