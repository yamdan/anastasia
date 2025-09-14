use crate::{
    cert::ParsedCert,
    circuit::Circuit,
    utils::{UtcTime, commit_attrs, field_to_hex, from_u8_array_to_fr_vec, hex_to_field},
};

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

pub fn prove(
    circuit: &Circuit,
    cert: Vec<u8>,
    now: Option<DateTime<Utc>>,
    authority_key_id: Vec<u8>,
    issuer_pk_x: Vec<u8>,
    issuer_pk_y: Vec<u8>,
    prev_cmt: String,
    prev_cmt_r: String,
    max_extra_extension_len: usize,
) -> Result<(Vec<u8>, String, String), String> {
    println!(
        "Debug: max_extra_extension_len = {}",
        max_extra_extension_len
    );

    let parsed_cert =
        ParsedCert::from_der(&cert).map_err(|e| format!("Failed to parse cert: {}", e))?;

    let mut rng = OsRng;
    let next_cmt_r = Fr::rand(&mut rng);
    let next_cmt = commit_attrs(
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
            .try_into()
            .map_err(|_| "authority_key_id must be 20 bytes")?,
        issuer_pk_x
            .try_into()
            .map_err(|_| "issuer_pk_x must be 32 bytes")?,
        issuer_pk_y
            .try_into()
            .map_err(|_| "issuer_pk_y must be 32 bytes")?,
        hex_to_field(&prev_cmt)?,
        hex_to_field(&prev_cmt_r)?,
        next_cmt,
        next_cmt_r,
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
        field_to_hex(&next_cmt),
        field_to_hex(&next_cmt_r),
    ))
}

pub fn generate_witness(
    parsed_cert: ParsedCert,
    now: Option<DateTime<Utc>>,
    authority_key_id: [u8; 20],
    issuer_pk_x: [u8; 32],
    issuer_pk_y: [u8; 32],
    prev_cmt: Fr,
    prev_cmt_r: Fr,
    next_cmt: Fr,
    next_cmt_r: Fr,
    max_extra_extension_len: usize,
) -> Result<WitnessMap<GenericFieldElement<Fr>>, String> {
    let mut witness: Vec<Fr> = Vec::new();

    let datetime = now.unwrap_or_else(|| Utc::now());
    let now = UtcTime {
        year: datetime.year() as u16,
        month: datetime.month() as u8,
        day: datetime.day() as u8,
        hour: datetime.hour() as u8,
        minute: datetime.minute() as u8,
        second: datetime.second() as u8,
    };

    witness.extend(from_u8_array_to_fr_vec(&issuer_pk_x));
    witness.extend(from_u8_array_to_fr_vec(&issuer_pk_y));
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
    witness.extend(from_u8_array_to_fr_vec(&authority_key_id));
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
    witness.push(prev_cmt);
    witness.push(prev_cmt_r);
    witness.push(next_cmt);
    witness.push(next_cmt_r);

    let mut witness_map = WitnessMap::new();
    for (i, witness) in witness.iter().enumerate() {
        witness_map.insert(Witness(i as u32), FieldElement::from_repr(*witness));
    }

    Ok(witness_map)
}
