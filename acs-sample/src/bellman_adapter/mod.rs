//! Bellman integration with explicit field compatibility and shape checking.

/// ACS-to-Bellman constraint translation.
pub mod adapter;
use acs::cs::{
    error::ConstructionError, trival::TrivalCircuitDriver, CircuitDriver, Field as ACS_Field,
    Script,
};
use acs::field::bn256::Bn256PrimeField;
use franklin_crypto::bellman::pairing::ff::{Field as BellmanScalar, PrimeField};
use franklin_crypto::bellman::{
    bn256::{Bn256, Fr},
    plonk::better_better_cs::cs::ConstraintSystem,
    Engine, SynthesisError,
};
use franklin_crypto::plonk::circuit::allocated_num::{AllocatedNum, Num};
use rescue_poseidon::{generic_hash, PoseidonParams};

use crate::circuit::MainCircuit;

/// A compile-time bridge between an ACS field and an engine's scalar field.
///
/// Implementations must preserve canonical integer values in both directions.
/// There is deliberately no blanket implementation: equal limb counts do not
/// imply equal moduli or limb ordering.
pub trait BellmanField<E: Engine>: ACS_Field {
    /// Converts into the engine scalar field.
    fn into_engine(self) -> Result<E::Fr, ConstructionError>;

    /// Converts from the engine scalar field.
    fn from_engine(value: E::Fr) -> Result<Self, ConstructionError>;
}

impl BellmanField<Bn256> for Bn256PrimeField {
    fn into_engine(self) -> Result<Fr, ConstructionError> {
        let mut repr = Fr::zero().into_repr();
        let limbs: <Self as ACS_Field>::Repr = self.into();
        let limbs = limbs.as_ref();
        if limbs.len() != 6 || repr.as_mut().len() != 4 {
            return Err(ConstructionError::FieldConversion);
        }
        repr.as_mut()
            .copy_from_slice(&[limbs[5], limbs[4], limbs[3], limbs[2]]);
        Fr::from_repr(repr).map_err(|_| ConstructionError::FieldConversion)
    }

    fn from_engine(value: Fr) -> Result<Self, ConstructionError> {
        let mut repr: <Self as ACS_Field>::Repr = Self::zero().into();
        let limbs = value.into_repr();
        let limbs = limbs.as_ref();
        if limbs.len() != 4 || repr.as_mut().len() != 6 {
            return Err(ConstructionError::FieldConversion);
        }
        repr.as_mut()
            .copy_from_slice(&[0, 0, limbs[3], limbs[2], limbs[1], limbs[0]]);
        Ok(Self::from(repr))
    }
}

/// Converts an ACS field through an explicitly implemented field bridge.
pub fn convert_field<E: Engine, F: BellmanField<E>>(value: F) -> Result<E::Fr, ConstructionError> {
    value.into_engine()
}

/// Converts an engine scalar through an explicitly implemented field bridge.
pub fn convert_acs_field<E: Engine, F: BellmanField<E>>(
    value: E::Fr,
) -> Result<F, ConstructionError> {
    F::from_engine(value)
}

/// Synthesizes against an assignment-free reference shape.
///
/// Both witness and constraint passes must match the reference exactly, which
/// rejects gadgets that branch allocations or constraints on witness values.
pub fn synthesize_circuit<E, F, CS>(
    circuit: &MainCircuit<F>,
    script: Script<F>,
    cs: &mut CS,
) -> Result<(), SynthesisError>
where
    E: Engine,
    F: BellmanField<E>,
    CS: ConstraintSystem<E>,
{
    let shape_driver = TrivalCircuitDriver::new_trival(script);
    let assignment_free_circuit = MainCircuit::new(None, None, [None; 3], None);
    assignment_free_circuit
        .instantiate(&shape_driver)
        .map_err(|_| SynthesisError::Unsatisfiable)?;

    // Setup assemblies do not require assignments. Proving/testing assemblies
    // will evaluate the allocation closures and reject missing values.
    let witness_driver = TrivalCircuitDriver::new_wtns(script);
    let witness_driver = match circuit.instantiate(&witness_driver) {
        Ok(()) => {
            shape_driver
                .ensure_same_shape(&witness_driver)
                .map_err(|_| SynthesisError::Unsatisfiable)?;
            Some(witness_driver)
        }
        Err(ConstructionError::AssignmentMissing) => None,
        Err(_) => return Err(SynthesisError::Unsatisfiable),
    };

    let public_inputs = shape_driver.public_input_indices();
    let signal_count = shape_driver.signal_count();
    let mut vars = Vec::with_capacity(signal_count);
    for index in 0..signal_count {
        let converted = witness_driver
            .as_ref()
            .map(|driver| {
                driver
                    .wtns_get(index)
                    .map_err(|_| SynthesisError::AssignmentMissing)
                    .and_then(|value| {
                        convert_field::<E, F>(value).map_err(|_| SynthesisError::AssignmentMissing)
                    })
            })
            .transpose()?;
        let variable = if public_inputs.binary_search(&index).is_ok() {
            Num::Variable(AllocatedNum::alloc_input(cs, || {
                converted.ok_or(SynthesisError::AssignmentMissing)
            })?)
        } else {
            Num::alloc(cs, converted)?
        };
        vars.push(variable);
    }

    let constraint_driver =
        CircuitDriver::new(script, false, Some(adapter::BellmanAdapter::new(cs, vars)));
    circuit
        .instantiate(&constraint_driver)
        .map_err(|_| SynthesisError::Unsatisfiable)?;
    shape_driver
        .ensure_same_shape(&constraint_driver)
        .map_err(|_| SynthesisError::Unsatisfiable)
}

/// Native witness script for the Poseidon patch used by the sample circuit.
pub fn script(
    key: &str,
    params: Vec<Bn256PrimeField>,
    formulas: Vec<Option<Bn256PrimeField>>,
) -> Result<Vec<Option<Bn256PrimeField>>, ConstructionError> {
    match key {
        "Poseidon" => {
            let [param] = params.as_slice() else {
                return Err(ConstructionError::UnsupportedPatch);
            };
            if *param != Bn256PrimeField::from_str("2")? {
                return Err(ConstructionError::UnsupportedPatch);
            }
            let [left, right] = formulas.as_slice() else {
                return Err(ConstructionError::UnsupportedPatch);
            };
            let (Some(left), Some(right)) = (left, right) else {
                return Ok(vec![None]);
            };

            const RATE: usize = 2;
            const WIDTH: usize = 3;
            let poseidon_params = PoseidonParams::<Bn256, RATE, WIDTH>::default();
            let input = [
                convert_field::<Bn256, Bn256PrimeField>(*left)?,
                convert_field::<Bn256, Bn256PrimeField>(*right)?,
            ];
            let result = generic_hash(&poseidon_params, &input, None);
            let output = result
                .first()
                .cloned()
                .ok_or(ConstructionError::AdapterError)?;
            Ok(vec![Some(convert_acs_field::<Bn256, Bn256PrimeField>(
                output,
            )?)])
        }
        _ => Err(ConstructionError::UnsupportedPatch),
    }
}

#[cfg(test)]
mod tests {
    use acs::cs::Field;
    use franklin_crypto::{
        bellman::plonk::better_better_cs::cs::{TrivialAssembly, Width4MainGateWithDNext},
        plonk::circuit::Width4WithCustomGates,
    };

    use super::*;

    fn field(value: &str) -> Bn256PrimeField {
        Bn256PrimeField::from_str(value).unwrap()
    }

    #[test]
    fn field_conversion_round_trips() {
        let value = field("123456789");
        let converted = convert_field::<Bn256, _>(value).unwrap();
        assert_eq!(
            convert_acs_field::<Bn256, Bn256PrimeField>(converted),
            Ok(value)
        );
    }

    #[test]
    fn patch_script_validates_key_parameter_and_arity() {
        assert_eq!(
            script("unknown", vec![], vec![]),
            Err(ConstructionError::UnsupportedPatch)
        );
        assert_eq!(
            script("Poseidon", vec![], vec![None, None]),
            Err(ConstructionError::UnsupportedPatch)
        );
        assert_eq!(
            script("Poseidon", vec![field("3")], vec![None, None]),
            Err(ConstructionError::UnsupportedPatch)
        );
        assert_eq!(
            script("Poseidon", vec![field("2")], vec![None]),
            Err(ConstructionError::UnsupportedPatch)
        );
        assert_eq!(
            script("Poseidon", vec![field("2")], vec![None, None]),
            Ok(vec![None])
        );
    }

    fn poseidon(left: Bn256PrimeField, right: Bn256PrimeField) -> Bn256PrimeField {
        script("Poseidon", vec![field("2")], vec![Some(left), Some(right)])
            .unwrap()
            .into_iter()
            .next()
            .flatten()
            .unwrap()
    }

    fn sample_circuit(
        root_override: Option<Bn256PrimeField>,
    ) -> (MainCircuit<Bn256PrimeField>, Bn256PrimeField) {
        let nonce = field("7");
        let index = field("5");
        let siblings = [field("11"), field("13"), field("17")];
        let mut root = poseidon(nonce, nonce);
        for (is_right, sibling) in [true, false, true].into_iter().zip(siblings) {
            root = if is_right {
                poseidon(sibling, root)
            } else {
                poseidon(root, sibling)
            };
        }
        (
            MainCircuit::new(
                Some(nonce),
                Some(index),
                siblings.map(Some),
                Some(root_override.unwrap_or(root)),
            ),
            root,
        )
    }

    #[test]
    fn bellman_synthesis_binds_and_satisfies_the_public_root() {
        let (circuit, expected_root) = sample_circuit(None);
        let mut assembly =
            TrivialAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();

        synthesize_circuit(&circuit, script, &mut assembly).unwrap();

        assert_eq!(assembly.num_inputs, 1);
        assert_eq!(
            assembly.input_assingments,
            vec![convert_field::<Bn256, _>(expected_root).unwrap()]
        );
        assert!(assembly.is_satisfied());
        assembly.finalize();
        assert!(assembly.is_finalized);
    }

    #[test]
    fn bellman_synthesis_rejects_an_incorrect_root() {
        let (invalid, _) = sample_circuit(Some(field("1")));
        let mut assembly =
            TrivialAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();

        assert!(matches!(
            synthesize_circuit(&invalid, script, &mut assembly),
            Err(SynthesisError::Unsatisfiable)
        ));
    }

    #[test]
    fn bellman_setup_synthesizes_without_witness_assignments() {
        use franklin_crypto::bellman::plonk::better_better_cs::cs::SetupAssembly;

        let circuit = MainCircuit::new(None, None, [None; 3], None);
        let mut assembly =
            SetupAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();

        synthesize_circuit(&circuit, script, &mut assembly).unwrap();

        assert_eq!(assembly.num_inputs, 1);
        assert!(assembly.input_assingments.is_empty());
    }
}
