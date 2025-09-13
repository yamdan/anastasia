use std::io::Write;

use crate::circuit::Circuit;

use ark_bn254::Fr;
use flate2::{Compression, write::GzEncoder};
use noir::{
    acir_field::GenericFieldElement, barretenberg::prove::prove_ultra_honk,
    native_types::WitnessMap,
};

pub fn prove(circuit: &Circuit, cert: Vec<u8>, now: Option<u64>) -> Result<Vec<u8>, String> {
    let initial_witness = generate_witness(circuit, cert, now)?;

    let proof_with_public_inputs = prove_ultra_honk(
        &circuit.bytecode,
        initial_witness,
        circuit.verification_key.clone(),
        false,
    )?;
    //let (proof, _) = split_honk_proof(&proof_with_public_inputs, circuit.public_input_size)
    //    .ok_or("Failed to split honk proof")?;
    let proof = proof_with_public_inputs; // TODO: remove public inputs from proof

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&proof)
        .map_err(|e| format!("Failed to write proof to encoder: {}", e))?;
    let compressed_proof = encoder
        .finish()
        .map_err(|e| format!("Failed to finish compression of proof: {}", e))?;

    Ok(compressed_proof)
}

pub fn generate_witness(
    circuit: &Circuit,
    cert: Vec<u8>,
    now: Option<u64>,
) -> Result<WitnessMap<GenericFieldElement<Fr>>, String> {
    let witness = WitnessMap::new(); // TODO
    Ok(witness)
}
