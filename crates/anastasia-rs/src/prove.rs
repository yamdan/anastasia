use std::io::Write;

use crate::{cert::ParsedCert, circuit::Circuit, utils::to_fixed_array};

use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_std::rand::rngs::OsRng;
use chrono::{Datelike, Timelike, Utc};
use flate2::{Compression, write::GzEncoder};
use noir::{
    acir_field::GenericFieldElement, barretenberg::prove::prove_ultra_honk_keccak,
    native_types::WitnessMap,
};

#[derive(Debug, Clone, Copy)]
pub struct UtcTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

pub fn prove(circuit: &Circuit, cert: Vec<u8>, now: Option<UtcTime>) -> Result<Vec<u8>, String> {
    let initial_witness = generate_witness(
        circuit,
        cert,
        now,
        vec![0u8; 124],
        [0u8; 20],
        [0u8; 32],
        [0u8; 32],
        Fr::from(0u64),
        Fr::from(0u64),
    )?;

    let proof_with_public_inputs = prove_ultra_honk_keccak(
        &circuit.bytecode,
        initial_witness,
        circuit.verification_key.clone(),
        false,
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
    now: Option<UtcTime>,
    issuer: Vec<u8>,
    authority_key_id: [u8; 20],
    issuer_pk_x: [u8; 32],
    issuer_pk_y: [u8; 32],
    prev_cmt: Fr,
    prev_cmt_r: Fr,
) -> Result<WitnessMap<GenericFieldElement<Fr>>, String> {
    let witness = WitnessMap::new(); // TODO

    let parsed_cert =
        ParsedCert::from_der(&cert).map_err(|e| format!("Failed to parse cert: {}", e))?;
    let now = now.unwrap_or_else(|| {
        let datetime = Utc::now();
        UtcTime {
            year: datetime.year() as u16,
            month: datetime.month() as u8,
            day: datetime.day() as u8,
            hour: datetime.hour() as u8,
            minute: datetime.minute() as u8,
            second: datetime.second() as u8,
        }
    });

    let issuer = to_fixed_array::<124>(&issuer)?;

    let mut rng = OsRng;
    let next_cmt_r = Fr::rand(&mut rng);

    Ok(witness)
}
