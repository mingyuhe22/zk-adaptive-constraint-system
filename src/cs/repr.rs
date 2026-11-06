//! Opaque witness-side values used to allocate derived signals.

use crate::cs::*;
use std::ops::{self};
use std::rc::Rc;

/// Witness-side representation of a formula.
///
/// Arithmetic on this type computes assignments only; it emits no constraint.
/// Gadget authors must constrain every signal allocated from a representation.
/// Operator overloads treat cross-circuit arithmetic as a programmer error and
/// panic; use the checked `try_*` methods when circuit identity is dynamic.
#[must_use = "formula representations only affect a circuit when allocated and constrained"]
pub struct FormulaRepr<F: Field, A: Adapter<F>> {
    val: Option<F::Repr>,
    pub(crate) rc_circuit: Rc<CircuitDriver<F, A>>,
}
impl<F: Field, A: Adapter<F>> FormulaRepr<F, A> {
    fn ensure_same_circuit(&self, other: &Self) -> Result<(), ConstructionError> {
        if Rc::ptr_eq(&self.rc_circuit, &other.rc_circuit) {
            Ok(())
        } else {
            Err(ConstructionError::CircuitMismatch)
        }
    }

    /// Creates a representation tied to `circuit`.
    pub fn new(val: Option<F>, circuit: &Rc<CircuitDriver<F, A>>) -> FormulaRepr<F, A> {
        FormulaRepr {
            val: val.map(Into::into),
            rc_circuit: Rc::clone(circuit),
        }
    }
    /// Returns the optional witness value.
    ///
    /// This is for witness generation and tests only. Branching circuit
    /// structure on the returned value violates the two-pass shape invariant.
    pub fn val(&self) -> Option<F> {
        self.val.map(F::from)
    }
    /// Computes a witness-side multiplicative inverse.
    pub fn inv(&self) -> Result<Self, ConstructionError> {
        Ok(FormulaRepr::new(
            match self.val() {
                Some(val) => Some(val.inv().ok_or(ConstructionError::DivisionByZero)?),
                None => None,
            },
            &self.rc_circuit,
        ))
    }

    /// Adds representations after checking their circuit identity.
    pub fn try_add(self, rhs: Self) -> Result<Self, ConstructionError> {
        self.ensure_same_circuit(&rhs)?;
        Ok(Self {
            val: match (self.val, rhs.val) {
                (Some(left), Some(right)) => Some(left + right),
                _ => None,
            },
            rc_circuit: Rc::clone(&self.rc_circuit),
        })
    }

    /// Multiplies representations after checking their circuit identity.
    pub fn try_mul(self, rhs: Self) -> Result<Self, ConstructionError> {
        self.ensure_same_circuit(&rhs)?;
        Ok(Self {
            val: match (self.val, rhs.val) {
                (Some(left), Some(right)) => Some(left * right),
                _ => None,
            },
            rc_circuit: Rc::clone(&self.rc_circuit),
        })
    }

    /// Subtracts representations after checking their circuit identity.
    pub fn try_sub(self, rhs: Self) -> Result<Self, ConstructionError> {
        self.ensure_same_circuit(&rhs)?;
        Ok(Self {
            val: match (self.val, rhs.val) {
                (Some(left), Some(right)) => Some(left - right),
                _ => None,
            },
            rc_circuit: Rc::clone(&self.rc_circuit),
        })
    }

    /// Computes integer bitwise-and after checking circuit identity.
    pub fn try_bitand(self, rhs: Self) -> Result<Self, ConstructionError> {
        self.ensure_same_circuit(&rhs)?;
        Ok(Self {
            val: match (self.val, rhs.val) {
                (Some(left), Some(right)) => Some(left & right),
                _ => None,
            },
            rc_circuit: Rc::clone(&self.rc_circuit),
        })
    }

    /// Computes integer bitwise-or after checking circuit identity.
    pub fn try_bitor(self, rhs: Self) -> Result<Self, ConstructionError> {
        self.ensure_same_circuit(&rhs)?;
        Ok(Self {
            val: match (self.val, rhs.val) {
                (Some(left), Some(right)) => Some(left | right),
                _ => None,
            },
            rc_circuit: Rc::clone(&self.rc_circuit),
        })
    }
}
impl<F: Field, A: Adapter<F>> ops::Add for FormulaRepr<F, A> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        self.try_add(rhs)
            .expect("cannot add representations from different circuits")
    }
}
impl<F: Field, A: Adapter<F>> ops::Mul for FormulaRepr<F, A> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        self.try_mul(rhs)
            .expect("cannot multiply representations from different circuits")
    }
}
impl<F: Field, A: Adapter<F>> ops::Neg for FormulaRepr<F, A> {
    type Output = Self;
    fn neg(self) -> Self {
        Self {
            val: self.val.map(ops::Neg::neg),
            rc_circuit: Rc::clone(&self.rc_circuit),
        }
    }
}
impl<F: Field, A: Adapter<F>> ops::Sub for FormulaRepr<F, A> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        self.try_sub(rhs)
            .expect("cannot subtract representations from different circuits")
    }
}
impl<F: Field, A: Adapter<F>> ops::Div for FormulaRepr<F, A> {
    type Output = Result<Self, ConstructionError>;
    fn div(self, rhs: Self) -> Result<Self, ConstructionError> {
        if !Rc::ptr_eq(&self.rc_circuit, &rhs.rc_circuit) {
            return Err(ConstructionError::CircuitMismatch);
        }
        Ok(Self {
            val: match (self.val, rhs.val) {
                (Some(a), Some(b)) => Some(a.div(b).ok_or(ConstructionError::DivisionByZero)?),
                _ => None,
            },
            rc_circuit: Rc::clone(&self.rc_circuit),
        })
    }
}
impl<F: Field, A: Adapter<F>> Clone for FormulaRepr<F, A> {
    fn clone(&self) -> Self {
        Self {
            val: self.val,
            rc_circuit: Rc::clone(&self.rc_circuit),
        }
    }
}
impl<F: Field, A: Adapter<F>> ops::Shl<usize> for FormulaRepr<F, A> {
    type Output = Self;

    fn shl(self, rhs: usize) -> Self::Output {
        Self {
            val: self.val.map(|a| a.shl(rhs)),
            rc_circuit: Rc::clone(&self.rc_circuit),
        }
    }
}

impl<F: Field, A: Adapter<F>> ops::Shr<usize> for FormulaRepr<F, A> {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        Self {
            val: self.val.map(|a| a.shr(rhs)),
            rc_circuit: Rc::clone(&self.rc_circuit),
        }
    }
}

impl<F: Field, A: Adapter<F>> ops::BitAnd for FormulaRepr<F, A> {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.try_bitand(rhs)
            .expect("cannot combine representations from different circuits")
    }
}
impl<F: Field, A: Adapter<F>> ops::BitOr for FormulaRepr<F, A> {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.try_bitor(rhs)
            .expect("cannot combine representations from different circuits")
    }
}
impl<F: Field, A: Adapter<F>> ops::BitAnd<F> for FormulaRepr<F, A> {
    type Output = Self;

    fn bitand(self, rhs: F) -> Self::Output {
        let rhs = FormulaRepr::new(Some(rhs), &self.rc_circuit);
        self.bitand(rhs)
    }
}
impl<F: Field, A: Adapter<F>> ops::BitOr<F> for FormulaRepr<F, A> {
    type Output = Self;

    fn bitor(self, rhs: F) -> Self::Output {
        let rhs = FormulaRepr::new(Some(rhs), &self.rc_circuit);
        self.bitor(rhs)
    }
}
