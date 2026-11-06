//! Range-constrained integers with unsigned and two's-complement comparisons.

use super::bool::Bool;
use acs::cs::{error::ConstructionError, formula::Formula, Adapter, CircuitDriver, Field};
use std::rc::Rc;

/// A field signal constrained to the unsigned range `0..2^BITS`.
#[must_use = "range-constrained numbers must be used by another gadget"]
pub struct Num<F: Field, A: Adapter<F>, const BITS: usize> {
    num: Formula<F, A>,
    bits: [Bool<F, A>; BITS],
}
impl<F: Field, A: Adapter<F>, const BITS: usize> Num<F, A, BITS> {
    fn validate_width() -> Result<(), ConstructionError> {
        if BITS == 0 {
            return Err(ConstructionError::InvalidBitWidth);
        }
        if BITS > F::CAPACITY_BITS {
            return Err(ConstructionError::BitWidthExceedsFieldCapacity {
                requested: BITS,
                max_supported: F::CAPACITY_BITS,
            });
        }
        Ok(())
    }

    /// Allocates and range-constrains a number.
    pub fn load(
        rc_circuit: &Rc<CircuitDriver<F, A>>,
        num: Option<F>,
    ) -> Result<Self, ConstructionError> {
        Self::validate_width()?;
        Self::from_formula(Formula::load(num, rc_circuit)?)
    }

    /// Range-constrains an existing formula through little-endian bit decomposition.
    pub fn from_formula(mut num: Formula<F, A>) -> Result<Self, ConstructionError> {
        Self::validate_width()?;

        let mut bits_vec = Vec::with_capacity(BITS);
        let mut f = num.dupl()?;
        let mut coefficient = F::one();
        for i in 0..BITS {
            let bit = Formula::alloc(&((num.repr() >> i) & F::one()))?;
            let mut bit = Bool::new(bit)?;
            f = f - bit.dupl()?.into_formula() * coefficient;
            bits_vec.push(bit);
            coefficient = coefficient + coefficient;
        }
        let circuit = f.get_circuit();
        f.eq_to(Formula::constant(F::zero(), &circuit))?;
        let bits = bits_vec
            .try_into()
            .map_err(|_| ConstructionError::InvalidArrayLength)?;
        Ok(Self { num, bits })
    }

    pub(crate) fn bit_mut(&mut self, index: usize) -> Option<&mut Bool<F, A>> {
        self.bits.get_mut(index)
    }

    fn ensure_same_circuit(&self, other: &Self) -> Result<(), ConstructionError> {
        if Rc::ptr_eq(&self.num.get_circuit(), &other.num.get_circuit()) {
            Ok(())
        } else {
            Err(ConstructionError::CircuitMismatch)
        }
    }

    /// Returns whether `self` is smaller than `other` as an unsigned integer.
    pub fn lt(&mut self, other: &mut Self) -> Result<Bool<F, A>, ConstructionError> {
        self.ensure_same_circuit(other)?;
        let mut less = Bool::constant(false, &self.num.get_circuit());

        // Process from least to most significant. Each new bit supersedes the
        // lower-bit result unless both current bits are equal.
        for index in 0..BITS {
            let mut lhs = self.bits[index].dupl()?;
            let mut rhs = other.bits[index].dupl()?;
            let mut lhs_not = lhs.not()?;
            let mut current_less = lhs_not.and(&mut rhs)?;
            let mut current_equal = lhs.equals(&mut rhs)?;
            let mut lower_less = current_equal.and(&mut less)?;
            less = current_less.or(&mut lower_less)?;
        }
        Ok(less)
    }

    /// Returns whether `self` is at most `other` as an unsigned integer.
    pub fn le(&mut self, other: &mut Self) -> Result<Bool<F, A>, ConstructionError> {
        other.lt(self)?.not()
    }

    /// Returns whether `self` is greater than `other` as an unsigned integer.
    pub fn gt(&mut self, other: &mut Self) -> Result<Bool<F, A>, ConstructionError> {
        other.lt(self)
    }

    /// Returns whether `self` is at least `other` as an unsigned integer.
    pub fn ge(&mut self, other: &mut Self) -> Result<Bool<F, A>, ConstructionError> {
        self.lt(other)?.not()
    }

    /// Signed less-than using `BITS`-wide two's-complement interpretation.
    pub fn slt(&mut self, other: &mut Self) -> Result<Bool<F, A>, ConstructionError> {
        self.ensure_same_circuit(other)?;
        let mut lhs_sign = self.bits[BITS - 1].dupl()?;
        let mut rhs_sign = other.bits[BITS - 1].dupl()?;
        let mut signs_differ = lhs_sign.xor(&mut rhs_sign)?;
        let mut unsigned_less = self.lt(other)?;
        signs_differ.select(&mut lhs_sign, &mut unsigned_less)
    }

    /// Signed less-than-or-equal using two's-complement interpretation.
    pub fn sle(&mut self, other: &mut Self) -> Result<Bool<F, A>, ConstructionError> {
        other.slt(self)?.not()
    }

    /// Signed greater-than using two's-complement interpretation.
    pub fn sgt(&mut self, other: &mut Self) -> Result<Bool<F, A>, ConstructionError> {
        other.slt(self)
    }

    /// Signed greater-than-or-equal using two's-complement interpretation.
    pub fn sge(&mut self, other: &mut Self) -> Result<Bool<F, A>, ConstructionError> {
        self.slt(other)?.not()
    }
}

#[cfg(test)]
mod tests {
    use acs::{
        cs::{error::ConstructionError, trival::TrivalCircuitDriver, Field},
        field::bn256::Bn256PrimeField,
    };

    use super::Num;

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

    #[test]
    fn decomposes_honest_witness_into_little_endian_bits() {
        let circuit = TrivalCircuitDriver::new_wtns(no_patch);
        let Num { bits, .. } = Num::<_, (), 4>::load(&circuit, Some(field("13"))).unwrap();
        let bits: Vec<_> = bits
            .into_iter()
            .map(|bit| bit.into_formula().repr().val().unwrap())
            .collect();
        assert_eq!(bits, vec![field("1"), field("0"), field("1"), field("1")]);
    }

    #[test]
    fn rejects_zero_width_and_avoids_host_shift_overflow() {
        let zero_width_circuit = TrivalCircuitDriver::new_wtns(no_patch);
        assert!(matches!(
            Num::<_, (), 0>::load(&zero_width_circuit, Some(field("0"))),
            Err(ConstructionError::InvalidBitWidth)
        ));

        let wide_circuit = TrivalCircuitDriver::new_wtns(no_patch);
        let _ = Num::<_, (), 65>::load(&wide_circuit, Some(field("1"))).unwrap();
        assert_eq!(wide_circuit.wtns_len(), Ok(66));

        let oversized_circuit = TrivalCircuitDriver::new_wtns(no_patch);
        assert_eq!(
            Num::<_, (), 254>::load(&oversized_circuit, Some(field("1"))).map(|_| ()),
            Err(ConstructionError::BitWidthExceedsFieldCapacity {
                requested: 254,
                max_supported: 253,
            })
        );
        assert_eq!(oversized_circuit.wtns_len(), Ok(0));
    }

    fn bool_value(value: super::Bool<Bn256PrimeField, ()>) -> bool {
        value.into_formula().repr().val().unwrap() == field("1")
    }

    #[test]
    fn comparisons_match_exhaustive_four_bit_truth_tables() {
        for lhs_value in 0..16 {
            for rhs_value in 0..16 {
                let circuit = TrivalCircuitDriver::new_wtns(no_patch);
                let mut lhs =
                    Num::<_, (), 4>::load(&circuit, Some(field(&lhs_value.to_string()))).unwrap();
                let mut rhs =
                    Num::<_, (), 4>::load(&circuit, Some(field(&rhs_value.to_string()))).unwrap();

                assert_eq!(bool_value(lhs.lt(&mut rhs).unwrap()), lhs_value < rhs_value);
                assert_eq!(
                    bool_value(lhs.le(&mut rhs).unwrap()),
                    lhs_value <= rhs_value
                );
                assert_eq!(bool_value(lhs.gt(&mut rhs).unwrap()), lhs_value > rhs_value);
                assert_eq!(
                    bool_value(lhs.ge(&mut rhs).unwrap()),
                    lhs_value >= rhs_value
                );

                let signed_lhs = if lhs_value >= 8 {
                    lhs_value - 16
                } else {
                    lhs_value
                };
                let signed_rhs = if rhs_value >= 8 {
                    rhs_value - 16
                } else {
                    rhs_value
                };
                assert_eq!(
                    bool_value(lhs.slt(&mut rhs).unwrap()),
                    signed_lhs < signed_rhs
                );
                assert_eq!(
                    bool_value(lhs.sle(&mut rhs).unwrap()),
                    signed_lhs <= signed_rhs
                );
                assert_eq!(
                    bool_value(lhs.sgt(&mut rhs).unwrap()),
                    signed_lhs > signed_rhs
                );
                assert_eq!(
                    bool_value(lhs.sge(&mut rhs).unwrap()),
                    signed_lhs >= signed_rhs
                );
            }
        }
    }
}
