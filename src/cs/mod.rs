//! Constraint-system interfaces and the stateful circuit driver.

use formula::*;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::{self};
use std::{cell::RefCell, rc::Rc};

use self::error::ConstructionError;
use self::repr::FormulaRepr;
/// Construction and adapter error types.
pub mod error;
/// Move-only circuit formulas and their constraint operations.
pub mod formula;
/// Opaque witness-side representations used to derive new signals.
pub mod repr;
/// A driver alias for passes that do not emit constraints.
pub mod trival;

/// Integer representation required by [`Field`].
pub trait FieldRepr:
    Clone
    + Copy
    + ops::Add<Output = Self>
    + ops::Mul<Output = Self>
    + ops::Sub<Output = Self>
    + ops::Div<Output = Option<Self>>
    + ops::Neg<Output = Self>
    + ops::Shl<usize, Output = Self>
    + ops::Shr<usize, Output = Self>
    + ops::BitAnd<Output = Self>
    + ops::BitOr<Output = Self>
    + PartialEq
    + Eq
    + AsRef<[u64]>
    + AsMut<[u64]>
    + Debug
{
}
/// Field operations required by the adaptive constraint system.
pub trait Field:
    Clone
    + Copy
    + ops::Add<Output = Self>
    + ops::Mul<Output = Self>
    + ops::Sub<Output = Self>
    + ops::Neg<Output = Self>
    + From<Self::Repr>
    + Into<Self::Repr>
    + PartialEq
    + Eq
    + Debug
{
    /// Largest bit width for which binary decomposition is injective in this field.
    const CAPACITY_BITS: usize;
    /// Canonical integer representation of a field element.
    type Repr: FieldRepr;
    /// Multiplicative identity.
    fn one() -> Self;
    /// Additive identity.
    fn zero() -> Self;
    /// Additive inverse of one.
    fn neg1() -> Self;
    /// Multiplicative inverse, or `None` for zero.
    fn inv(self) -> Option<Self>;
    /// Field division, or `None` when `other` is zero.
    fn div(self, other: Self) -> Option<Self> {
        Some(self * other.inv()?)
    }
    /// Parses a canonical decimal value or a hexadecimal value prefixed by `0x`.
    fn from_str(s: &str) -> Result<Self, ConstructionError>;
    /// Formats the canonical field value in decimal.
    fn to_str(self) -> String;
}
/// Backend that consumes serialized adaptive constraints.
pub trait Adapter<F: Field> {
    /// Emits one expression or patch constraint into the backend.
    fn do_constraint(&mut self, constraint: Constraint<F>) -> Result<(), ConstructionError>;
}
/// Binary operators encoded in prefix-form expressions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operator {
    /// Field addition.
    Add,
    /// Field multiplication.
    Mul,
}
/// One token in a prefix-form constraint expression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Elem<F: Field> {
    /// Allocated signal index.
    Idx(usize),
    /// Constant field element.
    Constant(F),
    /// Binary operation followed by its two operands.
    Operator(Operator),
}
/// Adapter-specific operation with fixed parameters and signal indices.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Patch<F: Field> {
    /// Adapter-defined patch identifier.
    pub key: String,
    /// Constant patch parameters.
    pub params: Vec<F>,
    /// Input indices followed by output indices.
    pub indexes: Vec<usize>,
}
/// Constraint emitted by a circuit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Constraint<F: Field> {
    /// Prefix-form expression constrained to equal zero.
    Expr(Vec<Elem<F>>),
    /// Adapter-specific operation.
    Patch(Patch<F>),
}
impl<F: Field, A: Adapter<F>> From<Formula<F, A>> for Constraint<F> {
    fn from(f: Formula<F, A>) -> Self {
        Self::Expr(f.elems)
    }
}
struct Acs<F: Field, A: Adapter<F>> {
    adapter: A,
    _marker: PhantomData<F>,
}
impl<F: Field, A: Adapter<F>> Acs<F, A> {
    fn new(adapter: A) -> Self {
        Self {
            adapter,
            _marker: PhantomData,
        }
    }
    fn enforce(&mut self, c: Constraint<F>) -> Result<(), ConstructionError> {
        self.adapter.do_constraint(c)
    }
}
struct Witness<F: Field>(Vec<Option<F>>);
impl<F: Field> Witness<F> {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn assign(&mut self, idx: usize, val: F) -> Result<(), ConstructionError> {
        if self.0.len() <= idx {
            let new_len = idx.checked_add(1).ok_or(ConstructionError::IndexOverflow)?;
            self.0.resize(new_len, None);
        }
        match self.0[idx] {
            Some(_) => Err(ConstructionError::WitnessAssignmentError),
            None => {
                self.0[idx] = Some(val);
                Ok(())
            }
        }
    }
    fn get(&self, idx: usize) -> Option<F> {
        self.0.get(idx).copied().flatten()
    }
}
struct CircuitDriverCore<F: Field, A: Adapter<F>> {
    idx_counter: usize,
    cs: Option<Acs<F, A>>,
    wtns: Option<Witness<F>>,
    public_inputs: BTreeSet<usize>,
    constraints: Vec<Constraint<F>>,
}
impl<F: Field, A: Adapter<F>> CircuitDriverCore<F, A> {
    fn new(wtns_switch: bool, adapter: Option<A>) -> Self {
        let cs = adapter.map(Acs::new);
        let wtns = if wtns_switch {
            Some(Witness::new())
        } else {
            None
        };
        Self {
            idx_counter: 0,
            cs,
            wtns,
            public_inputs: BTreeSet::new(),
            constraints: Vec::new(),
        }
    }
    fn new_wtns() -> Self {
        let wtns = Some(Witness::new());
        Self {
            idx_counter: 0,
            cs: None,
            wtns,
            public_inputs: BTreeSet::new(),
            constraints: Vec::new(),
        }
    }
    fn new_trival() -> Self {
        Self {
            idx_counter: 0,
            cs: None,
            wtns: None,
            public_inputs: BTreeSet::new(),
            constraints: Vec::new(),
        }
    }
    fn enforce(&mut self, c: Constraint<F>) -> Result<(), ConstructionError> {
        self.constraints.push(c.clone());
        if let Some(cs) = &mut self.cs {
            cs.enforce(c)?;
        }
        Ok(())
    }
    fn enforce_patch(&mut self, patch: Patch<F>) -> Result<(), ConstructionError> {
        self.enforce(Constraint::Patch(patch))
    }
    fn assign(&mut self, idx: usize, val: Option<F>) -> Result<(), ConstructionError> {
        if let Some(wtns) = &mut self.wtns {
            if let Some(val) = val {
                wtns.assign(idx, val)?;
            } else {
                return Err(ConstructionError::AssignmentMissing);
            }
        }
        Ok(())
    }
    fn allocate(&mut self, val: Option<F>) -> Result<usize, ConstructionError> {
        if self.wtns.is_some() && val.is_none() {
            return Err(ConstructionError::AssignmentMissing);
        }
        let idx = self.pop_idx()?;
        self.assign(idx, val)?;
        Ok(idx)
    }
    fn pop_idx(&mut self) -> Result<usize, ConstructionError> {
        let idx = self.idx_counter;
        self.idx_counter = self
            .idx_counter
            .checked_add(1)
            .ok_or(ConstructionError::IndexOverflow)?;
        Ok(idx)
    }
    fn add_input(&mut self, idx: usize) {
        self.public_inputs.insert(idx);
    }
    fn wtns_get(&self, idx: usize) -> Result<F, ConstructionError> {
        self.wtns
            .as_ref()
            .ok_or(ConstructionError::WitnessUnavailable)?
            .get(idx)
            .ok_or(ConstructionError::WitnessValueMissing)
    }

    fn has_same_shape<B: Adapter<F>>(&self, other: &CircuitDriverCore<F, B>) -> bool {
        self.idx_counter == other.idx_counter
            && self.public_inputs == other.public_inputs
            && self.constraints == other.constraints
    }
}
/// Native witness function for adapter-specific patches.
pub type Script<F> = fn(
    key: &str,
    params: Vec<F>,
    formulas: Vec<Option<F>>,
) -> Result<Vec<Option<F>>, ConstructionError>;

/// Shared circuit-construction state for witness and constraint passes.
pub struct CircuitDriver<F: Field, A: Adapter<F>> {
    core: RefCell<CircuitDriverCore<F, A>>,
    script: Script<F>,
}
impl<F: Field, A: Adapter<F>> CircuitDriver<F, A> {
    /// Creates a driver with independently selectable witness and adapter modes.
    pub fn new(script: Script<F>, wtns_switch: bool, adapter: Option<A>) -> Rc<Self> {
        Rc::new(Self {
            core: RefCell::new(CircuitDriverCore::new(wtns_switch, adapter)),
            script,
        })
    }
    /// Returns the assigned witness at `idx`.
    pub fn wtns_get(&self, idx: usize) -> Result<F, ConstructionError> {
        self.core.borrow().wtns_get(idx)
    }
    /// Returns the number of witness slots.
    pub fn wtns_len(&self) -> Result<usize, ConstructionError> {
        self.core
            .borrow()
            .wtns
            .as_ref()
            .map(|wtns| wtns.0.len())
            .ok_or(ConstructionError::WitnessUnavailable)
    }
    /// Returns public signal indices in deterministic allocation order.
    pub fn public_input_indices(&self) -> Vec<usize> {
        self.core.borrow().public_inputs.iter().copied().collect()
    }
    /// Returns the number of signals allocated by this driver.
    pub fn signal_count(&self) -> usize {
        self.core.borrow().idx_counter
    }
    /// Verifies that another construction pass produced the same circuit shape.
    pub fn ensure_same_shape<B: Adapter<F>>(
        &self,
        other: &CircuitDriver<F, B>,
    ) -> Result<(), ConstructionError> {
        if self.core.borrow().has_same_shape(&other.core.borrow()) {
            Ok(())
        } else {
            Err(ConstructionError::CircuitShapeMismatch)
        }
    }
    /// Creates a witness-only driver.
    pub fn new_wtns(script: Script<F>) -> Rc<Self> {
        Rc::new(Self {
            core: RefCell::new(CircuitDriverCore::new_wtns()),
            script,
        })
    }
    /// Creates a shape-only driver without witnesses or an adapter.
    pub fn new_trival(script: Script<F>) -> Rc<Self> {
        Rc::new(Self {
            core: RefCell::new(CircuitDriverCore::new_trival()),
            script,
        })
    }
}
fn patch_with_output_count<F: Field, A: Adapter<F>>(
    key: &str,
    params: Vec<F>,
    mut formulas: Vec<Formula<F, A>>,
    expected_outputs: usize,
) -> Result<Vec<Formula<F, A>>, ConstructionError> {
    let first = formulas.first().ok_or(ConstructionError::EmptyPatch)?;
    let circuit = first.get_circuit();
    if formulas
        .iter()
        .any(|formula| !Rc::ptr_eq(&circuit, &formula.rc_circuit))
    {
        return Err(ConstructionError::CircuitMismatch);
    }
    let output_values = (circuit.script)(
        key,
        params.clone(),
        formulas.iter().map(|f| f.repr().val()).collect(),
    )?;
    let actual = output_values.len();
    if actual != expected_outputs {
        return Err(ConstructionError::PatchOutputCountMismatch {
            expected: expected_outputs,
            actual,
        });
    }
    for formula in &mut formulas {
        let _ = formula.ensure_signal()?;
    }
    let outputs: Result<Vec<_>, _> = output_values
        .into_iter()
        .map(|value| Formula::alloc(&FormulaRepr::new(value, &circuit)))
        .collect();
    let outputs = outputs?;
    let idx_inputs: Result<Vec<_>, _> = formulas.iter().map(|x| x.get_idx()).collect();
    let mut indexes = idx_inputs?;
    for output in &outputs {
        indexes.push(output.get_idx()?);
    }
    let p = Patch::<F> {
        key: key.to_string(),
        params,
        indexes,
    };
    circuit.core.borrow_mut().enforce_patch(p)?;
    Ok(outputs)
}

/// Applies a patch whose output arity is fixed by the caller's type.
pub fn patch_array<F: Field, A: Adapter<F>, const OUTPUTS: usize>(
    key: &str,
    params: Vec<F>,
    formulas: Vec<Formula<F, A>>,
) -> Result<[Formula<F, A>; OUTPUTS], ConstructionError> {
    let outputs = patch_with_output_count(key, params, formulas, OUTPUTS)?;
    let actual = outputs.len();
    outputs
        .try_into()
        .map_err(|_| ConstructionError::PatchOutputCountMismatch {
            expected: OUTPUTS,
            actual,
        })
}
