use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_std::rand::rngs::OsRng;
use chrono::{DateTime, Datelike, Timelike, Utc};
use noir::{
    FieldElement,
    acir_field::GenericFieldElement,
    barretenberg::prove::prove_ultra_honk_keccak,
    native_types::{Witness, WitnessMap},
};

use crate::{
    cert::ParsedCert,
    circuit::Circuit,
    commit::commit_attrs,
    utils::{FromHexString, ToHexString, UtcTime, from_u8_array_to_fr_vec},
};

pub fn prove(
    circuit: &Circuit,
    parsed_cert: &ParsedCert,
    now: &DateTime<Utc>,
    authority_key_id: &Vec<u8>,
    issuer_pk_x: &Vec<u8>,
    issuer_pk_y: &Vec<u8>,
    prev_cmt_x: &String,
    prev_cmt_y: &String,
    prev_cmt_r: &String,
    max_extra_extension_len: usize,
) -> Result<(Vec<u8>, String, String, String), String> {
    println!(
        "Debug: max_extra_extension_len = {}",
        max_extra_extension_len
    );

    let mut rng = OsRng;
    let next_cmt_r = Fr::rand(&mut rng);
    let (next_cmt_x, next_cmt_y) = commit_attrs(
        parsed_cert.subject,
        parsed_cert.subject_key_identifier,
        parsed_cert.subject_pk_x,
        parsed_cert.subject_pk_y,
        next_cmt_r,
    )?;

    let initial_witness = generate_witness(
        parsed_cert,
        now,
        authority_key_id
            .as_slice()
            .try_into()
            .map_err(|_| "authority_key_id must be 20 bytes")?,
        issuer_pk_x
            .as_slice()
            .try_into()
            .map_err(|_| "issuer_pk_x must be 32 bytes")?,
        issuer_pk_y
            .as_slice()
            .try_into()
            .map_err(|_| "issuer_pk_y must be 32 bytes")?,
        &Fr::from_hex_string(&prev_cmt_x)?,
        &Fr::from_hex_string(&prev_cmt_y)?,
        &Fr::from_hex_string(&prev_cmt_r)?,
        &next_cmt_x,
        &next_cmt_y,
        &next_cmt_r,
        max_extra_extension_len,
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

    // let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    // encoder
    //     .write_all(&proof)
    //     .map_err(|e| format!("Failed to write proof to encoder: {}", e))?;
    // let compressed_proof = encoder
    //     .finish()
    //     .map_err(|e| format!("Failed to finish compression of proof: {}", e))?;

    let compressed_proof = proof; // TODO: enable compression

    Ok((
        compressed_proof,
        next_cmt_x.to_hex_string(),
        next_cmt_y.to_hex_string(),
        next_cmt_r.to_hex_string(),
    ))
}

pub fn generate_witness(
    parsed_cert: &ParsedCert,
    now: &DateTime<Utc>,
    authority_key_id: &[u8; 20],
    issuer_pk_x: &[u8; 32],
    issuer_pk_y: &[u8; 32],
    prev_cmt_x: &Fr,
    prev_cmt_y: &Fr,
    prev_cmt_r: &Fr, // TODO: change to lo and hi parts as GrumpkinFr
    next_cmt_x: &Fr,
    next_cmt_y: &Fr,
    next_cmt_r: &Fr, // TODO: change to lo and hi parts as GrumpkinFr
    max_extra_extension_len: usize,
) -> Result<WitnessMap<GenericFieldElement<Fr>>, String> {
    let mut witness: Vec<Fr> = Vec::new();

    let now = UtcTime {
        year: now.year() as u16,
        month: now.month() as u8,
        day: now.day() as u8,
        hour: now.hour() as u8,
        minute: now.minute() as u8,
        second: now.second() as u8,
    };

    witness.extend(from_u8_array_to_fr_vec(issuer_pk_x));
    witness.extend(from_u8_array_to_fr_vec(issuer_pk_y));
    witness.extend(from_u8_array_to_fr_vec(&parsed_cert.signature));
    witness.extend(from_u8_array_to_fr_vec(&parsed_cert.serial_number));
    witness.push(parsed_cert.serial_number_len.into());
    witness.extend(from_u8_array_to_fr_vec(&parsed_cert.issuer));
    witness.push(parsed_cert.issuer_len.into());
    witness.extend(from_u8_array_to_fr_vec(&parsed_cert.subject));
    witness.push(parsed_cert.subject_len.into());
    witness.extend(from_u8_array_to_fr_vec(&parsed_cert.subject_pk_x));
    witness.extend(from_u8_array_to_fr_vec(&parsed_cert.subject_pk_y));
    witness.extend(from_u8_array_to_fr_vec(&parsed_cert.subject_key_identifier));
    witness.extend(from_u8_array_to_fr_vec(
        &parsed_cert.authority_key_identifier,
    ));
    witness.extend(from_u8_array_to_fr_vec(authority_key_id));
    witness.push(parsed_cert.subject_key_identifier_index.into());
    witness.push(parsed_cert.authority_key_identifier_index.into());
    witness.push(parsed_cert.basic_constraints_ca_index.into());
    witness.push(parsed_cert.key_usage_key_cert_sign_index.into());
    witness.push(parsed_cert.key_usage_digital_signature_index.into());

    let mut extra_extension_array = vec![0u8; max_extra_extension_len];
    let copy_len = std::cmp::min(parsed_cert.extra_extension.len(), max_extra_extension_len);
    extra_extension_array[..copy_len].copy_from_slice(&parsed_cert.extra_extension[..copy_len]);

    witness.extend(from_u8_array_to_fr_vec(&extra_extension_array));
    witness.push(parsed_cert.extra_extension_len.into());
    witness.extend(from_u8_array_to_fr_vec(&parsed_cert.not_before));
    witness.extend(from_u8_array_to_fr_vec(&parsed_cert.not_after));
    witness.extend(from_u8_array_to_fr_vec(&now.to_bytes()));
    witness.push(*prev_cmt_x);
    witness.push(*prev_cmt_y);
    witness.push(*prev_cmt_r);
    witness.push(*next_cmt_x);
    witness.push(*next_cmt_y);
    witness.push(*next_cmt_r);

    let mut witness_map = WitnessMap::new();
    for (i, witness) in witness.iter().enumerate() {
        witness_map.insert(Witness(i as u32), FieldElement::from_repr(*witness));
    }

    Ok(witness_map)
}
