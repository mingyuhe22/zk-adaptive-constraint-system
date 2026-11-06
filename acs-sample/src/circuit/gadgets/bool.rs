//! Constrained boolean values and arithmetic combinators.

use acs::cs::{error::ConstructionError, formula::Formula, Adapter, CircuitDriver, Field};
use std::rc::Rc;

/// A formula constrained to be either zero or one.
#[must_use = "boolean formulas must be constrained or used by another gadget"]
pub struct Bool<F: Field, A: Adapter<F>>(Formula<F, A>);

impl<F: Field, A: Adapter<F>> Bool<F, A> {
    /// Constrains `formula` to be boolean.
    pub fn new(mut formula: Formula<F, A>) -> Result<Self, ConstructionError> {
        let circuit = formula.get_circuit();
        let constraint = formula.dupl()? * (formula.dupl()? - F::one());
        constraint.eq_to(Formula::constant(F::zero(), &circuit))?;
        Ok(Self(formula))
    }

    /// Creates a constant boolean without allocating a signal.
    pub fn constant(value: bool, circuit: &Rc<CircuitDriver<F, A>>) -> Self {
        Self(Formula::constant(
            if value { F::one() } else { F::zero() },
            circuit,
        ))
    }

    /// Duplicates this boolean, materializing it only when necessary.
    pub fn dupl(&mut self) -> Result<Self, ConstructionError> {
        Ok(Self(self.0.dupl()?))
    }

    /// Returns the underlying constrained formula.
    pub fn into_formula(self) -> Formula<F, A> {
        self.0
    }

    fn ensure_same_circuit(&self, other: &Self) -> Result<(), ConstructionError> {
        if Rc::ptr_eq(&self.0.get_circuit(), &other.0.get_circuit()) {
            Ok(())
        } else {
            Err(ConstructionError::CircuitMismatch)
        }
    }

    /// Computes logical negation.
    pub fn not(&mut self) -> Result<Self, ConstructionError> {
        Ok(Self(-self.0.dupl()? + F::one()))
    }

    /// Computes logical conjunction.
    pub fn and(&mut self, other: &mut Self) -> Result<Self, ConstructionError> {
        self.ensure_same_circuit(other)?;
        Ok(Self(self.0.dupl()? * other.0.dupl()?))
    }

    /// Computes logical disjunction.
    pub fn or(&mut self, other: &mut Self) -> Result<Self, ConstructionError> {
        self.ensure_same_circuit(other)?;
        let product = self.0.dupl()? * other.0.dupl()?;
        Ok(Self(self.0.dupl()? + other.0.dupl()? - product))
    }

    /// Computes exclusive-or.
    pub fn xor(&mut self, other: &mut Self) -> Result<Self, ConstructionError> {
        self.ensure_same_circuit(other)?;
        let two = F::one() + F::one();
        let product = self.0.dupl()? * other.0.dupl()?;
        Ok(Self(self.0.dupl()? + other.0.dupl()? - product * two))
    }

    /// Computes boolean equality.
    pub fn equals(&mut self, other: &mut Self) -> Result<Self, ConstructionError> {
        self.xor(other)?.not()
    }

    /// Selects between two booleans using `self` as the condition.
    pub fn select(
        &mut self,
        true_value: &mut Self,
        false_value: &mut Self,
    ) -> Result<Self, ConstructionError> {
        self.ensure_same_circuit(true_value)?;
        self.ensure_same_circuit(false_value)?;
        Ok(Self(
            self.cond_pick(true_value.0.dupl()?, false_value.0.dupl()?)?,
        ))
    }

    /// Selects between two formulas using `self` as the condition.
    pub fn cond_pick(
        &mut self,
        true_as: Formula<F, A>,
        mut false_as: Formula<F, A>,
    ) -> Result<Formula<F, A>, ConstructionError> {
        let condition_circuit = self.0.get_circuit();
        if !Rc::ptr_eq(&condition_circuit, &true_as.get_circuit())
            || !Rc::ptr_eq(&condition_circuit, &false_as.get_circuit())
        {
            return Err(ConstructionError::CircuitMismatch);
        }
        Ok((true_as - false_as.dupl()?) * self.0.dupl()? + false_as)
    }
}

#[cfg(test)]
mod tests {
    use acs::{
        cs::{error::ConstructionError, formula::Formula, trival::TrivalCircuitDriver, Field},
        field::bn256::Bn256PrimeField,
    };

    use super::Bool;

    fn field(value: &str) -> Bn256PrimeField {
        Bn256PrimeField::from_str(value).unwrap()
    }

    fn no_patch(
        _: &str,
        _: Vec<Bn256PrimeField>,
        _: Vec<Option<Bn256PrimeField>>,
    ) -> Result<Vec<Option<Bn256PrimeField>>, ConstructionError> {
        Err(ConstructionError::AdapterError)
    }

    fn load_bool(
        value: &str,
        circuit: &std::rc::Rc<TrivalCircuitDriver<Bn256PrimeField>>,
    ) -> Bool<Bn256PrimeField, ()> {
        Bool::new(Formula::load(Some(field(value)), circuit).unwrap()).unwrap()
    }

    #[test]
    fn boolean_operations_match_their_truth_tables() {
        for left in [false, true] {
            for right in [false, true] {
                let circuit = TrivalCircuitDriver::new_wtns(no_patch);
                let mut left_bool = load_bool(if left { "1" } else { "0" }, &circuit);
                let mut right_bool = load_bool(if right { "1" } else { "0" }, &circuit);

                let and = left_bool
                    .and(&mut right_bool)
                    .unwrap()
                    .into_formula()
                    .repr()
                    .val()
                    .unwrap();
                assert_eq!(and, field(if left && right { "1" } else { "0" }));

                let not = left_bool
                    .not()
                    .unwrap()
                    .into_formula()
                    .repr()
                    .val()
                    .unwrap();
                assert_eq!(not, field(if left { "0" } else { "1" }));

                let or = left_bool
                    .or(&mut right_bool)
                    .unwrap()
                    .into_formula()
                    .repr()
                    .val()
                    .unwrap();
                assert_eq!(or, field(if left || right { "1" } else { "0" }));

                let xor = left_bool
                    .xor(&mut right_bool)
                    .unwrap()
                    .into_formula()
                    .repr()
                    .val()
                    .unwrap();
                assert_eq!(xor, field(if left ^ right { "1" } else { "0" }));

                let equals = left_bool
                    .equals(&mut right_bool)
                    .unwrap()
                    .into_formula()
                    .repr()
                    .val()
                    .unwrap();
                assert_eq!(equals, field(if left == right { "1" } else { "0" }));
            }
        }
    }

    #[test]
    fn checked_constructor_rejects_non_boolean_witness() {
        let circuit = TrivalCircuitDriver::new_wtns(no_patch);
        let formula = Formula::load(Some(field("2")), &circuit).unwrap();
        assert!(matches!(
            Bool::new(formula),
            Err(ConstructionError::Unsatisfiable)
        ));
    }
}
