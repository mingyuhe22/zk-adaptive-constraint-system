use std::{cell::RefCell, rc::Rc};

use crate::{
    cs::{
        error::ConstructionError, formula::Formula, patch_array, Adapter, CircuitDriver,
        Constraint, Field,
    },
    field::bn256::Bn256PrimeField,
};

type TestField = Bn256PrimeField;

fn field(value: &str) -> TestField {
    TestField::from_str(value).expect("valid test field element")
}

fn square_script(
    key: &str,
    _: Vec<TestField>,
    formulas: Vec<Option<TestField>>,
) -> Result<Vec<Option<TestField>>, ConstructionError> {
    if key != "square" {
        return Err(ConstructionError::AdapterError);
    }
    let [value] = formulas.as_slice() else {
        return Err(ConstructionError::AdapterError);
    };
    Ok(vec![value.map(|value| value * value)])
}

fn no_patch_script(
    _: &str,
    _: Vec<TestField>,
    _: Vec<Option<TestField>>,
) -> Result<Vec<Option<TestField>>, ConstructionError> {
    Err(ConstructionError::AdapterError)
}

#[derive(Clone, Default)]
struct RecordingAdapter(Rc<RefCell<Vec<Constraint<TestField>>>>);

impl Adapter<TestField> for RecordingAdapter {
    fn do_constraint(
        &mut self,
        constraint: Constraint<TestField>,
    ) -> Result<(), ConstructionError> {
        self.0.borrow_mut().push(constraint);
        Ok(())
    }
}

#[test]
fn witness_generation_and_patch_outputs_are_stable() {
    let circuit = CircuitDriver::<TestField, ()>::new_wtns(square_script);
    let mut x = Formula::load(Some(field("5")), &circuit).unwrap();

    let _ = (x.dupl().unwrap().pow(6).unwrap() + field("5"))
        .to_input()
        .unwrap();
    let outputs = patch_array::<_, _, 1>("square", vec![], vec![x.dupl().unwrap()]).unwrap();

    assert_eq!(outputs.len(), 1);
    assert_eq!(circuit.wtns_len(), Ok(3));
    assert_eq!(circuit.wtns_get(0), Ok(field("5")));
    assert_eq!(circuit.wtns_get(1), Ok(field("15630")));
    assert_eq!(circuit.wtns_get(2), Ok(field("25")));
}

#[test]
fn pow_matches_repeated_multiplication_including_zero() {
    for exponent in 0..8 {
        let circuit = CircuitDriver::<TestField, ()>::new_wtns(no_patch_script);
        let value = Formula::load(Some(field("3")), &circuit)
            .unwrap()
            .pow(exponent)
            .unwrap()
            .repr()
            .val()
            .unwrap();
        let expected = (0..exponent).fold(TestField::one(), |acc, _| acc * field("3"));
        assert_eq!(value, expected, "incorrect result for exponent {exponent}");
    }
}

#[test]
fn complex_formula_is_materialized_only_once_by_dupl() {
    let adapter = RecordingAdapter::default();
    let constraints = Rc::clone(&adapter.0);
    let circuit = CircuitDriver::new(no_patch_script, false, Some(adapter));
    let x = Formula::load(None, &circuit).unwrap();
    let mut expression = x + field("1");

    let _ = expression.dupl().unwrap();
    let _ = expression.dupl().unwrap();

    let constraints = constraints.borrow();
    assert_eq!(constraints.len(), 1);
    assert!(matches!(constraints[0], Constraint::Expr(_)));
}

#[test]
fn empty_and_mixed_circuit_patches_return_errors() {
    assert!(matches!(
        patch_array::<TestField, (), 1>("square", vec![], vec![]),
        Err(ConstructionError::EmptyPatch)
    ));

    let left_circuit = CircuitDriver::<TestField, ()>::new_wtns(square_script);
    let right_circuit = CircuitDriver::<TestField, ()>::new_wtns(square_script);
    let left = Formula::load(Some(field("2")), &left_circuit).unwrap();
    let right = Formula::load(Some(field("3")), &right_circuit).unwrap();
    assert!(matches!(
        patch_array::<_, _, 1>("square", vec![], vec![left, right]),
        Err(ConstructionError::CircuitMismatch)
    ));
}

#[test]
fn equality_and_repr_division_reject_mixed_circuits() {
    let left_circuit = CircuitDriver::<TestField, ()>::new_wtns(no_patch_script);
    let right_circuit = CircuitDriver::<TestField, ()>::new_wtns(no_patch_script);
    let left = Formula::load(Some(field("6")), &left_circuit).unwrap();
    let right = Formula::load(Some(field("3")), &right_circuit).unwrap();

    assert_eq!(left.eq_to(right), Err(ConstructionError::CircuitMismatch));

    let left = Formula::load(Some(field("6")), &left_circuit).unwrap();
    let right = Formula::load(Some(field("3")), &right_circuit).unwrap();
    assert!(matches!(
        left.repr() / right.repr(),
        Err(ConstructionError::CircuitMismatch)
    ));

    let left = Formula::load(Some(field("6")), &left_circuit).unwrap();
    let right = Formula::load(Some(field("3")), &right_circuit).unwrap();
    assert!(matches!(
        left.try_add(right),
        Err(ConstructionError::CircuitMismatch)
    ));

    let left = Formula::load(Some(field("6")), &left_circuit).unwrap();
    let right = Formula::load(Some(field("3")), &right_circuit).unwrap();
    assert!(matches!(
        left.repr().try_mul(right.repr()),
        Err(ConstructionError::CircuitMismatch)
    ));
}

#[test]
fn witness_access_reports_mode_and_index_errors() {
    let witness_driver = CircuitDriver::<TestField, ()>::new_wtns(no_patch_script);
    let _ = Formula::load(Some(field("1")), &witness_driver).unwrap();
    assert_eq!(
        witness_driver.wtns_get(1),
        Err(ConstructionError::WitnessValueMissing)
    );

    let constraint_driver = CircuitDriver::<TestField, ()>::new_trival(no_patch_script);
    assert_eq!(
        constraint_driver.wtns_len(),
        Err(ConstructionError::WitnessUnavailable)
    );
    assert_eq!(
        constraint_driver.wtns_get(0),
        Err(ConstructionError::WitnessUnavailable)
    );

    let missing_driver = CircuitDriver::<TestField, ()>::new_wtns(no_patch_script);
    assert!(matches!(
        Formula::load(None, &missing_driver),
        Err(ConstructionError::AssignmentMissing)
    ));
    assert_eq!(missing_driver.signal_count(), 0);
    assert_eq!(missing_driver.wtns_len(), Ok(0));
}

#[test]
fn field_strings_are_checked_and_round_trip() {
    assert_eq!(field("16"), field("0x10"));
    let value = field("123456789");
    assert_eq!(TestField::from_str(&value.to_str()), Ok(value));

    for invalid in ["", "0x", "ff", "12z", "-1"] {
        assert_eq!(
            TestField::from_str(invalid),
            Err(ConstructionError::ParamFormatError)
        );
    }
    assert_eq!(
        TestField::from_str("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"),
        Err(ConstructionError::ParamFormatError)
    );
    assert_eq!(
        TestField::from_str(&"9".repeat(200)),
        Err(ConstructionError::ParamFormatError)
    );
}

#[test]
fn public_inputs_and_constraint_shapes_are_stable_across_passes() {
    let witness_driver = CircuitDriver::<TestField, ()>::new_wtns(no_patch_script);
    let mut witness_value = Formula::load(Some(field("2")), &witness_driver).unwrap();
    (witness_value.dupl().unwrap() + field("1"))
        .to_input()
        .unwrap()
        .eq_to(Formula::constant(field("3"), &witness_driver))
        .unwrap();

    let constraint_driver = CircuitDriver::<TestField, ()>::new_trival(no_patch_script);
    let mut constraint_value = Formula::load(Some(field("2")), &constraint_driver).unwrap();
    (constraint_value.dupl().unwrap() + field("1"))
        .to_input()
        .unwrap()
        .eq_to(Formula::constant(field("3"), &constraint_driver))
        .unwrap();

    assert_eq!(witness_driver.public_input_indices(), vec![1]);
    assert_eq!(witness_driver.signal_count(), 2);
    assert_eq!(witness_driver.ensure_same_shape(&constraint_driver), Ok(()));

    let divergent_driver = CircuitDriver::<TestField, ()>::new_trival(no_patch_script);
    let _ = Formula::load(Some(field("2")), &divergent_driver).unwrap();
    assert_eq!(
        witness_driver.ensure_same_shape(&divergent_driver),
        Err(ConstructionError::CircuitShapeMismatch)
    );
}

#[test]
fn fixed_arity_patch_rejects_script_mismatch_before_allocating_outputs() {
    let circuit = CircuitDriver::<TestField, ()>::new_wtns(square_script);
    let input = Formula::load(Some(field("4")), &circuit).unwrap();

    let result = patch_array::<_, _, 2>("square", vec![], vec![input]);

    assert!(matches!(
        result,
        Err(ConstructionError::PatchOutputCountMismatch {
            expected: 2,
            actual: 1,
        })
    ));
    assert_eq!(circuit.wtns_len(), Ok(1));
    assert_eq!(circuit.signal_count(), 1);
}
