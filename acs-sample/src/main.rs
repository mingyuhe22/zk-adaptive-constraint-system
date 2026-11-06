use acs::cs::{Field as ACS_Field, Script};
use franklin_crypto::bellman::{pairing::*, plonk::better_better_cs::cs::*, SynthesisError};
use serde::Deserialize;
use std::fs::File;
use std::io::Read;

use acs_sample::{
    bellman_adapter::{synthesize_circuit, BellmanField},
    circuit::MainCircuit,
};

#[derive(Clone)]
pub struct BellmanCircuit<F: ACS_Field> {
    params_filename: String,
    script: Script<F>,
}
impl<F: ACS_Field> BellmanCircuit<F> {
    pub fn new(params_filename: &str, script: Script<F>) -> Self {
        Self {
            params_filename: params_filename.to_string(),
            script,
        }
    }
}
impl<E: Engine, F: BellmanField<E> + for<'a> Deserialize<'a>> Circuit<E> for BellmanCircuit<F> {
    type MainGate = Width4MainGateWithDNext;

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let circuit: MainCircuit<F> = {
            let mut file = File::open(self.params_filename.as_str())?;
            let mut json_contents = String::new();
            file.read_to_string(&mut json_contents)?;
            serde_json::from_str(&json_contents).map_err(|_| SynthesisError::AssignmentMissing)?
        };
        synthesize_circuit(&circuit, self.script, cs)
    }
}
fn main() -> Result<(), SynthesisError> {
    use acs_sample::bellman_adapter::script;
    use franklin_crypto::bellman::bn256::Bn256;

    use franklin_crypto::plonk::circuit::Width4WithCustomGates;
    let params_filename = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "input.json".to_string());
    let circuit = BellmanCircuit::new(&params_filename, script);
    let mut cs = TrivialAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
    circuit.synthesize(&mut cs)?;
    if !cs.is_satisfied() {
        return Err(SynthesisError::Unsatisfiable);
    }
    cs.finalize();
    Ok(())
}
