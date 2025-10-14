use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_std::rand::rngs::OsRng;
use chrono::{DateTime, Datelike, Timelike, Utc};
use noir::{
    FieldElement,
    acir_field::GenericFieldElement,
    barretenberg::prove::prove_ultra_honk_keccak,
    native_types::{Witness, WitnessMap},
    utils::{
        ProofWithPublicInputs, get_num_public_inputs_from_circuit, parse_proof_with_public_inputs,
    },
};

use crate::{
    cert::ParsedCert,
    circuit::Circuit,
    commit::commit_attrs,
    hash_to_field::{HASH_TO_SCALAR, HashToScalar},
    pseudonym::generate_nym,
    utils::{UtcTime, from_u8_array_to_fr_vec},
};

pub const MAX_EXTRA_EXTENSION_LEN_CA: usize = 30;
pub const MAX_EXTRA_EXTENSION_LEN_EE: usize = 500;

pub fn prove_ca(
    circuit: &Circuit,
    parsed_cert: &ParsedCert,
    now: &DateTime<Utc>,
    authority_key_id: &[u8],
    issuer_pk_x: &[u8],
    issuer_pk_y: &[u8],
    prev_cmt_x: &Fr,
    prev_cmt_y: &Fr,
    prev_cmt_r: &Fr,
) -> Result<(ProofWithPublicInputs, Fr, Fr, Fr), String> {
    let mut rng = OsRng;
    let next_cmt_r = Fr::rand(&mut rng);
    let (next_cmt_x, next_cmt_y) = commit_attrs(
        parsed_cert.subject,
        parsed_cert.subject_key_identifier,
        parsed_cert.subject_pk_x,
        parsed_cert.subject_pk_y,
        next_cmt_r,
    )?;

    let initial_witness = generate_witness_ca(
        parsed_cert,
        now,
        authority_key_id
            .try_into()
            .map_err(|_| "authority_key_id must be 20 bytes")?,
        issuer_pk_x
            .try_into()
            .map_err(|_| "issuer_pk_x must be 32 bytes")?,
        issuer_pk_y
            .try_into()
            .map_err(|_| "issuer_pk_y must be 32 bytes")?,
        prev_cmt_x,
        prev_cmt_y,
        prev_cmt_r,
        &next_cmt_x,
        &next_cmt_y,
        &next_cmt_r,
        MAX_EXTRA_EXTENSION_LEN_CA,
    )?;

    let proof = prove_ultra_honk_keccak(
        &circuit.bytecode,
        initial_witness,
        circuit.verification_key.clone(),
        false,
        false,
    )?;

    let num_public_inputs = get_num_public_inputs_from_circuit(&circuit.bytecode).map_err(|e| {
        format!(
            "Failed to get number of public inputs from circuit bytecode: {}",
            e
        )
    })?;

    let proof_with_public_inputs = parse_proof_with_public_inputs(&proof, num_public_inputs)
        .map_err(|e| format!("Failed to parse proof with public inputs: {}", e))?;

    Ok((proof_with_public_inputs, next_cmt_x, next_cmt_y, next_cmt_r))
}

pub fn prove_ee(
    circuit: &Circuit,
    parsed_cert: &ParsedCert,
    now: &DateTime<Utc>,
    authority_key_id: &[u8],
    issuer_pk_x: &[u8],
    issuer_pk_y: &[u8],
    prev_cmt_x: &Fr,
    prev_cmt_y: &Fr,
    prev_cmt_r: &Fr,
    user_sk: &Fr,
    context: &str,
) -> Result<(ProofWithPublicInputs, Fr), String> {
    if context.is_empty() {
        return Err("Context cannot be empty".to_string());
    }
    let context_bytes = context.as_bytes();
    let context_field: Fr = HASH_TO_SCALAR.hash_to_scalar(context_bytes);

    let nym = generate_nym(
        user_sk,
        &(parsed_cert.subject_pk_x, parsed_cert.subject_pk_y),
        &context_field,
    )?;

    let initial_witness = generate_witness_ee(
        parsed_cert,
        now,
        authority_key_id
            .try_into()
            .map_err(|_| "authority_key_id must be 20 bytes")?,
        issuer_pk_x
            .try_into()
            .map_err(|_| "issuer_pk_x must be 32 bytes")?,
        issuer_pk_y
            .try_into()
            .map_err(|_| "issuer_pk_y must be 32 bytes")?,
        prev_cmt_x,
        prev_cmt_y,
        prev_cmt_r,
        user_sk,
        &context_field,
        &nym,
        MAX_EXTRA_EXTENSION_LEN_EE,
    )?;

    let proof = prove_ultra_honk_keccak(
        &circuit.bytecode,
        initial_witness,
        circuit.verification_key.clone(),
        false,
        false,
    )?;

    let num_public_inputs = get_num_public_inputs_from_circuit(&circuit.bytecode).map_err(|e| {
        format!(
            "Failed to get number of public inputs from circuit bytecode: {}",
            e
        )
    })?;

    let proof_with_public_inputs = parse_proof_with_public_inputs(&proof, num_public_inputs)
        .map_err(|e| format!("Failed to parse proof with public inputs: {}", e))?;

    Ok((proof_with_public_inputs, nym))
}

fn generate_witness_ca(
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
    let mut witness = generate_witness_common(
        parsed_cert,
        now,
        authority_key_id,
        issuer_pk_x,
        issuer_pk_y,
        prev_cmt_x,
        prev_cmt_y,
        prev_cmt_r,
        max_extra_extension_len,
    )?;

    witness.push(*next_cmt_x);
    witness.push(*next_cmt_y);
    witness.push(*next_cmt_r);

    witness.extend(from_u8_array_to_fr_vec(&parsed_cert.subject_key_identifier));
    witness.extend(from_u8_array_to_fr_vec(
        &parsed_cert.authority_key_identifier,
    ));
    witness.push(parsed_cert.subject_key_identifier_index.into());
    witness.push(parsed_cert.authority_key_identifier_index.into());
    witness.push(parsed_cert.basic_constraints_ca_index.into());
    witness.push(parsed_cert.key_usage_key_cert_sign_index.into());

    let mut witness_map = WitnessMap::new();
    for (i, witness) in witness.iter().enumerate() {
        witness_map.insert(Witness(i as u32), FieldElement::from_repr(*witness));
    }

    Ok(witness_map)
}

fn generate_witness_ee(
    parsed_cert: &ParsedCert,
    now: &DateTime<Utc>,
    authority_key_id: &[u8; 20],
    issuer_pk_x: &[u8; 32],
    issuer_pk_y: &[u8; 32],
    prev_cmt_x: &Fr,
    prev_cmt_y: &Fr,
    prev_cmt_r: &Fr, // TODO: change to lo and hi parts as GrumpkinFr
    user_sk: &Fr,
    context: &Fr,
    nym: &Fr,
    max_extra_extension_len: usize,
) -> Result<WitnessMap<GenericFieldElement<Fr>>, String> {
    let mut witness = generate_witness_common(
        parsed_cert,
        now,
        authority_key_id,
        issuer_pk_x,
        issuer_pk_y,
        prev_cmt_x,
        prev_cmt_y,
        prev_cmt_r,
        max_extra_extension_len,
    )?;

    witness.push(*user_sk);
    witness.push(*context);
    witness.push(*nym);

    let mut witness_map = WitnessMap::new();
    for (i, witness) in witness.iter().enumerate() {
        witness_map.insert(Witness(i as u32), FieldElement::from_repr(*witness));
    }

    Ok(witness_map)
}

fn generate_witness_common(
    parsed_cert: &ParsedCert,
    now: &DateTime<Utc>,
    authority_key_id: &[u8; 20],
    issuer_pk_x: &[u8; 32],
    issuer_pk_y: &[u8; 32],
    prev_cmt_x: &Fr,
    prev_cmt_y: &Fr,
    prev_cmt_r: &Fr, // TODO: change to lo and hi parts as GrumpkinFr
    max_extra_extension_len: usize,
) -> Result<Vec<Fr>, String> {
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

    // TODO: support other signature algorithms rather than just ES256
    let signature = parsed_cert.extract_normalized_es256_sig()?;
    witness.extend(from_u8_array_to_fr_vec(&signature));

    witness.extend(from_u8_array_to_fr_vec(&parsed_cert.serial_number));
    witness.push(parsed_cert.serial_number_len.into());
    witness.extend(from_u8_array_to_fr_vec(&parsed_cert.issuer));
    witness.push(parsed_cert.issuer_len.into());
    witness.extend(from_u8_array_to_fr_vec(&parsed_cert.subject));
    witness.push(parsed_cert.subject_len.into());
    witness.extend(from_u8_array_to_fr_vec(&parsed_cert.subject_pk_x));
    witness.extend(from_u8_array_to_fr_vec(&parsed_cert.subject_pk_y));
    witness.extend(from_u8_array_to_fr_vec(authority_key_id));

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

    Ok(witness)
}
