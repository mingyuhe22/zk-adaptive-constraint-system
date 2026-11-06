//! Move-only formulas that encode field expressions in prefix form.

use crate::cs::repr::*;
use crate::cs::*;
use std::fmt::{self, Display, Formatter};
use std::ops::{self};
use std::rc::Rc;
/// A move-only field expression associated with exactly one circuit driver.
///
/// Formulas intentionally do not implement `Clone`: call [`Formula::dupl`] to
/// reuse an expression. Complex expressions are materialized once as signals.
/// Operator overloads treat cross-circuit arithmetic as a programmer error and
/// panic; use the checked `try_*` methods when circuit identity is dynamic.
#[must_use = "formulas must be constrained, exposed, or used by another formula"]
pub struct Formula<F: Field, A: Adapter<F>> {
    pub(crate) elems: Vec<Elem<F>>,
    pub(crate) val: Option<F>,
    pub(crate) rc_circuit: Rc<CircuitDriver<F, A>>,
}
impl<F: Field, A: Adapter<F>> ops::Add for Formula<F, A> {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        self.try_add(other)
            .expect("cannot add formulas from different circuits")
    }
}
impl<F: Field, A: Adapter<F>> ops::Mul for Formula<F, A> {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        self.try_mul(other)
            .expect("cannot multiply formulas from different circuits")
    }
}
impl<F: Field, A: Adapter<F>> ops::Sub for Formula<F, A> {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        self.try_sub(other)
            .expect("cannot subtract formulas from different circuits")
    }
}
impl<F: Field, A: Adapter<F>> ops::Neg for Formula<F, A> {
    type Output = Self;
    fn neg(self) -> Self {
        self * F::neg1()
    }
}
impl<F: Field, A: Adapter<F>> ops::Add<F> for Formula<F, A> {
    type Output = Self;
    fn add(self, other: F) -> Self {
        let mut vec = vec![Elem::<F>::Operator(Operator::Add)];
        vec.extend(self.elems);
        vec.push(Elem::Constant(other));
        Formula {
            elems: vec,
            val: self.val.map(|a| a.add(other)),
            rc_circuit: Rc::clone(&self.rc_circuit),
        }
    }
}
impl<F: Field, A: Adapter<F>> ops::Mul<F> for Formula<F, A> {
    type Output = Self;
    fn mul(self, other: F) -> Self {
        let mut vec = vec![Elem::<F>::Operator(Operator::Mul)];
        vec.extend(self.elems);
        vec.push(Elem::Constant(other));
        Formula {
            elems: vec,
            val: self.val.map(|a| a.mul(other)),
            rc_circuit: Rc::clone(&self.rc_circuit),
        }
    }
}
impl<F: Field, A: Adapter<F>> ops::Sub<F> for Formula<F, A> {
    type Output = Self;
    fn sub(self, other: F) -> Self {
        self + other * F::neg1()
    }
}
impl<F: Field, A: Adapter<F>> ops::BitAnd for Formula<F, A> {
    type Output = Result<(), ConstructionError>;
    fn bitand(self, rhs: Self) -> Result<(), ConstructionError> {
        self.eq_to(rhs)
    }
}
impl<F: Field, A: Adapter<F>> ops::BitAnd<F> for Formula<F, A> {
    type Output = Result<(), ConstructionError>;
    fn bitand(self, rhs: F) -> Result<(), ConstructionError> {
        let rc_circuit = Rc::clone(&self.rc_circuit);
        self.eq_to(Formula::constant(rhs, &rc_circuit))
    }
}
impl<F: Field, A: Adapter<F>> Display for Formula<F, A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self.val {
                Some(val) => val.to_str(),
                None => "none".to_string(),
            }
        )
    }
}
impl<F: Field, A: Adapter<F>> Formula<F, A> {
    /// Adds formulas after checking that both belong to the same circuit.
    pub fn try_add(self, other: Self) -> Result<Self, ConstructionError> {
        if !Rc::ptr_eq(&self.rc_circuit, &other.rc_circuit) {
            return Err(ConstructionError::CircuitMismatch);
        }
        let mut elems = vec![Elem::<F>::Operator(Operator::Add)];
        elems.extend(self.elems);
        elems.extend(other.elems);
        Ok(Self {
            elems,
            val: match (self.val, other.val) {
                (Some(left), Some(right)) => Some(left + right),
                _ => None,
            },
            rc_circuit: Rc::clone(&self.rc_circuit),
        })
    }

    /// Multiplies formulas after checking that both belong to the same circuit.
    pub fn try_mul(self, other: Self) -> Result<Self, ConstructionError> {
        if !Rc::ptr_eq(&self.rc_circuit, &other.rc_circuit) {
            return Err(ConstructionError::CircuitMismatch);
        }
        let mut elems = vec![Elem::<F>::Operator(Operator::Mul)];
        elems.extend(self.elems);
        elems.extend(other.elems);
        Ok(Self {
            elems,
            val: match (self.val, other.val) {
                (Some(left), Some(right)) => Some(left * right),
                _ => None,
            },
            rc_circuit: Rc::clone(&self.rc_circuit),
        })
    }

    /// Subtracts formulas after checking that both belong to the same circuit.
    pub fn try_sub(self, other: Self) -> Result<Self, ConstructionError> {
        self.try_add(other * F::neg1())
    }

    /// Creates a constant formula without allocating a signal.
    pub fn constant(val: F, rc_circuit: &Rc<CircuitDriver<F, A>>) -> Self {
        Formula {
            elems: vec![Elem::Constant(val)],
            val: Some(val),
            rc_circuit: Rc::clone(rc_circuit),
        }
    }
    /// Allocates an unconstrained signal from a witness-side representation.
    ///
    /// The caller must add constraints relating the returned signal to existing
    /// formulas. This low-level operation is intended for gadget authors.
    pub fn alloc(fr: &FormulaRepr<F, A>) -> Result<Formula<F, A>, ConstructionError> {
        let idx = fr.rc_circuit.core.borrow_mut().allocate(fr.val())?;
        Ok(Formula {
            elems: vec![Elem::Idx(idx)],
            val: fr.val(),
            rc_circuit: Rc::clone(&fr.rc_circuit),
        })
    }
    /// Allocates a signal from an optional witness assignment.
    pub fn load(
        val: Option<F>,
        rc_circuit: &Rc<CircuitDriver<F, A>>,
    ) -> Result<Self, ConstructionError> {
        Self::alloc(&FormulaRepr::new(val, rc_circuit))
    }
    /// Returns an opaque representation for witness-side computations.
    ///
    /// Circuit structure must never branch on the contained witness value.
    pub fn repr(&self) -> FormulaRepr<F, A> {
        FormulaRepr::new(self.val, &self.rc_circuit)
    }
    fn is_leaf(&self) -> bool {
        self.elems.len() == 1
    }
    fn is_signal(&self) -> bool {
        matches!(self.elems.as_slice(), [Elem::Idx(_)])
    }
    fn shallow_copy(&self) -> Self {
        Self {
            elems: self.elems.clone(),
            val: self.val,
            rc_circuit: Rc::clone(&self.rc_circuit),
        }
    }
    pub(crate) fn ensure_signal(&mut self) -> Result<Formula<F, A>, ConstructionError> {
        if self.is_signal() {
            return Ok(self.shallow_copy());
        }
        let signal = Self::alloc(&self.repr())?;
        self.rc_circuit
            .core
            .borrow_mut()
            .enforce((self.shallow_copy() - signal.shallow_copy()).into())?;
        *self = signal.shallow_copy();
        Ok(signal)
    }
    /// Duplicates the formula, materializing a complex expression only once.
    pub fn dupl(&mut self) -> Result<Formula<F, A>, ConstructionError> {
        if self.is_leaf() {
            return Ok(self.shallow_copy());
        }
        self.ensure_signal()
    }
    pub(crate) fn get_idx(&self) -> Result<usize, ConstructionError> {
        if let [Elem::Idx(idx)] = self.elems.as_slice() {
            return Ok(*idx);
        }
        Err(ConstructionError::ExpectedSignal)
    }
    /// Returns the circuit driver that owns this formula.
    pub fn get_circuit(&self) -> Rc<CircuitDriver<F, A>> {
        Rc::clone(&self.rc_circuit)
    }
    /// Raises the formula to a non-negative integer power.
    pub fn pow(mut self, n: usize) -> Result<Self, ConstructionError> {
        if n == 0 {
            return Ok(Self::constant(F::one(), &self.rc_circuit));
        }
        let mut f = self.dupl()?;
        for _ in 0..n - 1 {
            f = f * self.dupl()?;
        }
        Ok(f)
    }
    /// Constrains this formula to equal `rhs`.
    pub fn eq_to(self, rhs: Self) -> Result<(), ConstructionError> {
        if !Rc::ptr_eq(&self.rc_circuit, &rhs.rc_circuit) {
            return Err(ConstructionError::CircuitMismatch);
        }
        if let (Some(a), Some(b)) = (self.val, rhs.val) {
            if a != b {
                return Err(ConstructionError::Unsatisfiable);
            }
        }
        let rc_circuit = Rc::clone(&self.rc_circuit);
        rc_circuit
            .core
            .borrow_mut()
            .enforce(Constraint::from(self - rhs))?;
        Ok(())
    }
    /// Materializes this formula and marks its signal as a public input.
    pub fn to_input(mut self) -> Result<Self, ConstructionError> {
        let f = self.ensure_signal()?;
        let idx = f.get_idx()?;
        f.rc_circuit.core.borrow_mut().add_input(idx);
        Ok(f)
    }
}
