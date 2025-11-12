use std::io::Write;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_std::rand::rngs::OsRng;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use ciborium::ser;
use flate2::{Compression, write::GzEncoder};
use noir::utils::ProofWithPublicInputs;
use serde::Serialize;
use serde_bytes::ByteBuf;

use crate::{
    cert::ParsedCert,
    circuit::{Circuit, CircuitMeta, setup_srs_from_bytecode_cached},
    hash_to_field::{HASH_TO_SCALAR, HashToScalar},
    utils::{FromHexString, ToBase64UrlString, ToHexString},
};

pub const DEFAULT_CIRCUIT_SIZE_LIMIT: u32 = 1_048_576; // == 2^20 (max supported by data/default_20.srs)

pub fn setup(srs_path: &str) -> Result<(), String> {
    setup_srs_from_bytecode_cached(DEFAULT_CIRCUIT_SIZE_LIMIT, srs_path)
}

pub fn generate_user_sk() -> Fr {
    let mut rng = OsRng;
    Fr::rand(&mut rng)
}

pub fn generate_user_sk_hex() -> String {
    let sk = generate_user_sk();
    sk.to_hex_string()
}

pub fn generate_nym(
    user_sk: &Fr,
    device_pk_x: &[u8],
    device_pk_y: &[u8],
    context: &str,
) -> Result<Fr, String> {
    let device_pk_x: &[u8; 32] = device_pk_x
        .try_into()
        .map_err(|_| "device_pk_x must be 32 bytes".to_string())?;
    let device_pk_y: &[u8; 32] = device_pk_y
        .try_into()
        .map_err(|_| "device_pk_y must be 32 bytes".to_string())?;
    let context_field = HASH_TO_SCALAR.hash_to_scalar(context.as_bytes());
    crate::pseudonym::generate_nym(user_sk, &(*device_pk_x, *device_pk_y), &context_field)
}

pub fn generate_nym_base64(
    user_sk: &str,
    device_pk_x: &[u8],
    device_pk_y: &[u8],
    context: &str,
) -> Result<String, String> {
    let user_sk_field = Fr::from_hex_string(user_sk)?;
    let nym = generate_nym(&user_sk_field, device_pk_x, device_pk_y, context)?;
    Ok(nym.to_base64_url_string())
}

#[derive(Debug)]
pub struct CommitResult {
    pub cmt_x: String,
    pub cmt_y: String,
    pub r: String,
}

pub fn commit_attrs(
    distinguished_name: &[u8],
    key_id: &[u8],
    pk_x: &[u8],
    pk_y: &[u8],
    r: Option<&str>,
) -> Result<CommitResult, String> {
    let mut rng = OsRng;
    let r = if let Some(r_hex) = r {
        let r_bytes = hex::decode(&r_hex).map_err(|e| format!("failed to decode r: {}", e))?;
        Fr::from_be_bytes_mod_order(&r_bytes)
    } else {
        Fr::rand(&mut rng)
    };

    let cmt = crate::commit::commit_attrs(
        {
            let mut padded_dn = distinguished_name.to_vec();
            if padded_dn.len() > 124 {
                return Err("distinguished name must be at most 124 bytes".to_string());
            }
            padded_dn.resize(124, 0u8);
            padded_dn
                .try_into()
                .map_err(|_| "distinguished name must be at most 124 bytes".to_string())?
        },
        key_id
            .try_into()
            .map_err(|_| "key_identifier must be 20 bytes".to_string())?,
        pk_x.try_into()
            .map_err(|_| "publickey_x must be 32 bytes".to_string())?,
        pk_y.try_into()
            .map_err(|_| "publickey_y must be 32 bytes".to_string())?,
        r,
    )?;

    let cmt_x_hex = cmt.0.to_hex_string();
    let cmt_y_hex = cmt.1.to_hex_string();
    let r_hex = r.to_hex_string();
    Ok(CommitResult {
        cmt_x: cmt_x_hex,
        cmt_y: cmt_y_hex,
        r: r_hex,
    })
}

#[derive(Debug)]
pub struct CAProofResult {
    /// The proof with public inputs
    pub proof_with_public_inputs: ProofWithPublicInputs,
    /// The next commitment x-coordinate
    pub next_cmt_x: String,
    /// The next commitment y-coordinate
    pub next_cmt_y: String,
    /// The random value used for the next commitment
    pub next_cmt_r: String,
}

pub fn prove_ca(
    circuit_meta: &CircuitMeta,
    cert: &[u8],
    now: Option<i64>,
    issuer_pk_x: &[u8],
    issuer_pk_y: &[u8],
    prev_cmt_x: &String,
    prev_cmt_y: &String,
    prev_cmt_r: &String,
    is_keccak_mode: bool,
) -> Result<CAProofResult, String> {
    let parsed_cert =
        ParsedCert::from_der(&cert).map_err(|e| format!("Failed to parse cert: {}", e))?;

    let now_datetime = match now {
        Some(ts) => DateTime::from_timestamp_secs(ts)
            .ok_or_else(|| "Invalid timestamp".to_string())?
            .with_timezone(&Utc),
        None => Utc::now(),
    };

    let circuit = Circuit::new(circuit_meta)?;

    let (proof_with_public_inputs, next_cmt_x, next_cmt_y, next_cmt_r) = crate::prove::prove_ca(
        &circuit,
        &parsed_cert,
        &now_datetime,
        issuer_pk_x,
        issuer_pk_y,
        &Fr::from_hex_string(prev_cmt_x)?,
        &Fr::from_hex_string(prev_cmt_y)?,
        &Fr::from_hex_string(prev_cmt_r)?,
        is_keccak_mode,
    )?;

    Ok(CAProofResult {
        proof_with_public_inputs: proof_with_public_inputs,
        next_cmt_x: next_cmt_x.to_hex_string(),
        next_cmt_y: next_cmt_y.to_hex_string(),
        next_cmt_r: next_cmt_r.to_hex_string(),
    })
}

#[derive(Debug)]
pub struct EEProofResult {
    /// The proof with public inputs
    pub proof_with_public_inputs: ProofWithPublicInputs,
    /// The pseudonym generated with the proof
    pub nym: String,
}

pub fn prove_ee(
    circuit_meta: &CircuitMeta,
    cert: &[u8],
    now: Option<i64>,
    issuer_pk_x: &[u8],
    issuer_pk_y: &[u8],
    prev_cmt_x: &String,
    prev_cmt_y: &String,
    prev_cmt_r: &String,
    authority_key_id: &[u8],
    user_sk: &str,
    context: &str,
    is_keccak_mode: bool,
) -> Result<EEProofResult, String> {
    let user_sk = Fr::from_hex_string(user_sk)?;

    let parsed_cert =
        ParsedCert::from_der(&cert).map_err(|e| format!("Failed to parse cert: {}", e))?;

    let now_datetime = match now {
        Some(ts) => DateTime::from_timestamp_secs(ts)
            .ok_or_else(|| "Invalid timestamp".to_string())?
            .with_timezone(&Utc),
        None => Utc::now(),
    };

    let circuit = Circuit::new(circuit_meta)?;

    let (proof_with_public_inputs, nym) = crate::prove::prove_ee(
        &circuit,
        &parsed_cert,
        &now_datetime,
        issuer_pk_x,
        issuer_pk_y,
        &Fr::from_hex_string(prev_cmt_x)?,
        &Fr::from_hex_string(prev_cmt_y)?,
        &Fr::from_hex_string(prev_cmt_r)?,
        authority_key_id,
        &user_sk,
        context,
        is_keccak_mode,
    )?;

    Ok(EEProofResult {
        proof_with_public_inputs,
        nym: nym.to_base64_url_string(),
    })
}

#[derive(Debug)]
pub struct ChainProofResult {
    /// The timestamp of the proof
    pub now: i64,
    /// The pseudonym generated with the proof
    pub nym: Fr,
    /// The CBOR-encoded proofs and commitments used in the proof chain
    pub proofs_and_commitments: Vec<u8>,
}

#[derive(Serialize, Debug)]
pub struct ProofsAndCommitments {
    #[serde(rename = "p")]
    pub proofs: Vec<ByteBuf>,
    #[serde(rename = "c")]
    pub commitments: Vec<(ByteBuf, ByteBuf)>,
}

pub fn prove_chain(
    subroot_circuit_meta: &CircuitMeta,
    intermediate_circuits_meta: &[CircuitMeta],
    leaf_circuit_meta: &CircuitMeta,
    root_cert: &[u8],
    subroot_cert: &[u8],
    intermediate_certs: &[&[u8]],
    leaf_cert: &[u8],
    now: Option<i64>,
    user_sk: &Fr,
    context: &str,
    is_keccak_mode: bool,
) -> Result<ChainProofResult, String> {
    if intermediate_circuits_meta.len() != intermediate_certs.len() {
        return Err(
            "Number of intermediate circuits must match number of intermediate certificates"
                .to_string(),
        );
    }

    let now_datetime = match now {
        Some(ts) => chrono::DateTime::from_timestamp_secs(ts)
            .ok_or_else(|| "Invalid timestamp".to_string())?
            .with_timezone(&chrono::Utc),
        None => chrono::Utc::now(),
    };

    let mut proofs = Vec::with_capacity(intermediate_certs.len() + 2);
    let mut commitments = Vec::with_capacity(intermediate_certs.len() + 1);

    // Parse the root certificate to get the initial issuer public key and authority key identifier
    let parsed_root_cert = ParsedCert::from_der(&root_cert)
        .map_err(|e| format!("Failed to parse root cert: {}", e))?;
    let mut issuer_pk_x = parsed_root_cert.subject_pk_x;
    let mut issuer_pk_y = parsed_root_cert.subject_pk_y;

    // Prove for the subroot CA certificate
    let parsed_subroot_cert =
        ParsedCert::from_der(&subroot_cert).map_err(|e| format!("Failed to parse cert: {}", e))?;
    let subroot_circuit = Circuit::new(&subroot_circuit_meta)?;
    let (subroot_proof_with_public_inputs, next_cmt_x, next_cmt_y, next_cmt_r) =
        crate::prove::prove_subroot(
            &subroot_circuit,
            &parsed_subroot_cert,
            &now_datetime,
            &issuer_pk_x.to_vec(),
            &issuer_pk_y.to_vec(),
            is_keccak_mode,
        )?;
    proofs.push(subroot_proof_with_public_inputs.proof);
    println!("Subroot proof generated: {}", subroot_circuit.id);

    let next_cmt_x_bytes = next_cmt_x.into_bigint().to_bytes_be();
    let next_cmt_y_bytes = next_cmt_y.into_bigint().to_bytes_be();
    commitments.push((next_cmt_x_bytes, next_cmt_y_bytes));

    let mut prev_cmt_x = next_cmt_x;
    let mut prev_cmt_y = next_cmt_y;
    let mut prev_cmt_r = next_cmt_r;
    let mut authority_key_id = parsed_subroot_cert.subject_key_identifier;
    issuer_pk_x = parsed_subroot_cert.subject_pk_x;
    issuer_pk_y = parsed_subroot_cert.subject_pk_y;

    // Prove for each intermediate certificate in the chain
    for (circuit_meta, cert) in intermediate_circuits_meta.iter().zip(intermediate_certs) {
        let parsed_cert =
            ParsedCert::from_der(&cert).map_err(|e| format!("Failed to parse cert: {}", e))?;
        let circuit = Circuit::new(circuit_meta)?;
        let (ca_proof_with_public_inputs, next_cmt_x, next_cmt_y, next_cmt_r) =
            crate::prove::prove_ca(
                &circuit,
                &parsed_cert,
                &now_datetime,
                &issuer_pk_x.to_vec(),
                &issuer_pk_y.to_vec(),
                &prev_cmt_x,
                &prev_cmt_y,
                &prev_cmt_r,
                is_keccak_mode,
            )?;
        proofs.push(ca_proof_with_public_inputs.proof);
        println!("Intermediate proof generated: {}", circuit.id);

        let next_cmt_x_bytes = next_cmt_x.into_bigint().to_bytes_be();
        let next_cmt_y_bytes = next_cmt_y.into_bigint().to_bytes_be();
        commitments.push((next_cmt_x_bytes, next_cmt_y_bytes));

        prev_cmt_x = next_cmt_x;
        prev_cmt_y = next_cmt_y;
        prev_cmt_r = next_cmt_r;
        authority_key_id = parsed_cert.subject_key_identifier;
        issuer_pk_x = parsed_cert.subject_pk_x;
        issuer_pk_y = parsed_cert.subject_pk_y;
    }

    // Prove for the leaf certificate
    let parsed_leaf_cert = ParsedCert::from_der(&leaf_cert)
        .map_err(|e| format!("Failed to parse leaf cert: {}", e))?;
    let leaf_circuit = Circuit::new(leaf_circuit_meta)?;
    let (ee_proof_with_public_inputs, nym) = crate::prove::prove_ee(
        &leaf_circuit,
        &parsed_leaf_cert,
        &now_datetime,
        &issuer_pk_x.to_vec(),
        &issuer_pk_y.to_vec(),
        &prev_cmt_x,
        &prev_cmt_y,
        &prev_cmt_r,
        &authority_key_id.to_vec(),
        user_sk,
        context,
        is_keccak_mode,
    )?;
    proofs.push(ee_proof_with_public_inputs.proof);
    println!("Leaf proof generated: {}", leaf_circuit.id);

    // serialize proofs_and_commitments to CBOR
    let proofs_and_commitments = ProofsAndCommitments {
        proofs: proofs.into_iter().map(ByteBuf::from).collect(),
        commitments: commitments
            .into_iter()
            .map(|(x, y)| (ByteBuf::from(x), ByteBuf::from(y)))
            .collect(),
    };
    let mut proofs_and_commitments_cbor = Vec::new();
    ser::into_writer(&proofs_and_commitments, &mut proofs_and_commitments_cbor)
        .map_err(|e| format!("Failed to serialize proof_and_commitments to CBOR: {}", e))?;

    // compress the CBOR data with gzip
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&proofs_and_commitments_cbor)
        .map_err(|e| format!("Failed to write proof to compression encoder: {}", e))?;
    let compressed_proof = encoder
        .finish()
        .map_err(|e| format!("Failed to finish compression of proof: {}", e))?;

    Ok(ChainProofResult {
        now: now_datetime.timestamp(),
        nym,
        proofs_and_commitments: compressed_proof,
    })
}

#[derive(Debug)]
pub struct ChainProofResultBase64 {
    /// The timestamp of the proof
    pub now: i64,
    /// The pseudonym generated with the proof
    pub nym: String,
    /// The CBOR-encoded proofs and commitments used in the proof chain
    pub proofs_and_commitments: String,
}

pub fn prove_chain_base64(
    subroot_circuits_meta: &CircuitMeta,
    intermediate_circuits_meta: &[CircuitMeta],
    leaf_circuit_meta: &CircuitMeta,
    root_cert: &[u8],
    subroot_cert: &[u8],
    intermediate_certs: &[&[u8]],
    leaf_cert: &[u8],
    now: Option<i64>,
    user_sk: &str,
    context: &str,
    is_keccak_mode: bool,
) -> Result<ChainProofResultBase64, String> {
    let user_sk_bytes =
        hex::decode(user_sk).map_err(|e| format!("Failed to decode user_sk: {}", e))?;
    if user_sk_bytes.len() > 32 {
        return Err(format!(
            "user_sk must be at most 32 bytes (64 hex characters), got {} bytes",
            user_sk_bytes.len()
        ));
    }
    let user_sk = Fr::from_be_bytes_mod_order(&user_sk_bytes);

    let result = prove_chain(
        subroot_circuits_meta,
        intermediate_circuits_meta,
        leaf_circuit_meta,
        root_cert,
        subroot_cert,
        intermediate_certs,
        leaf_cert,
        now,
        &user_sk,
        context,
        is_keccak_mode,
    )?;
    let proofs_and_commitments = URL_SAFE_NO_PAD.encode(result.proofs_and_commitments);

    Ok(ChainProofResultBase64 {
        now: result.now,
        nym: result.nym.to_base64_url_string(),
        proofs_and_commitments,
    })
}

pub fn prove_chain_as_key_attestation_jwt(
    subroot_circuits_meta: &CircuitMeta,
    intermediate_circuits_meta: &[CircuitMeta],
    leaf_circuit_meta: &CircuitMeta,
    root_cert: &[u8],
    subroot_cert: &[u8],
    intermediate_certs: &[&[u8]],
    leaf_cert: &[u8],
    now: Option<i64>,
    user_sk: &str,
    context: &str,
    is_keccak_mode: bool,
) -> Result<String, String> {
    let result = prove_chain_base64(
        subroot_circuits_meta,
        intermediate_circuits_meta,
        leaf_circuit_meta,
        root_cert,
        subroot_cert,
        intermediate_certs,
        leaf_cert,
        now,
        user_sk,
        context,
        is_keccak_mode,
    )?;

    let mut x5c = Vec::new();
    x5c.push(leaf_circuit_meta.id.clone());
    for circuit_meta in intermediate_circuits_meta.iter().rev() {
        x5c.push(circuit_meta.id.clone());
    }
    x5c.push(subroot_circuits_meta.id.clone());
    x5c.push(STANDARD.encode(root_cert));

    let header = serde_json::json!({
        "typ": "key-attestation+jwt",
        "alg": "ANASTASIA-AKA",
        "x5c": x5c,
    });

    let payload = serde_json::json!({
        "iat": result.now,
        "attested_keys": [
            {
                "kty": "oct",
                "k": result.nym,
                "kid": context,
            }
        ],
    });

    let header_bytes =
        serde_json::to_vec(&header).map_err(|e| format!("Failed to serialize header: {}", e))?;
    let payload_bytes =
        serde_json::to_vec(&payload).map_err(|e| format!("Failed to serialize payload: {}", e))?;

    let jwt = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header_bytes),
        URL_SAFE_NO_PAD.encode(payload_bytes),
        result.proofs_and_commitments
    );
    Ok(jwt)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_ff::AdditiveGroup;
    use serial_test::serial;

    #[test]
    fn test_setup() {
        let result = setup("../anastasia-rs/data/default_20.srs");
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_user_sk() {
        let sk = generate_user_sk();
        assert!(sk != Fr::ZERO);
    }

    #[test]
    fn test_generate_user_sk_hex() {
        let sk = generate_user_sk_hex();
        assert!(sk.len() == 64);
    }

    #[test]
    fn test_generate_nym() {
        let user_sk = Fr::from_hex_string("deadbeef").unwrap();
        let pk_x = [
            0xb4, 0x46, 0x2b, 0xe1, 0x47, 0x16, 0x55, 0x9d, 0x26, 0xf1, 0x2e, 0x60, 0x4f, 0xed,
            0xe1, 0x53, 0x39, 0xd2, 0x5a, 0xa4, 0xf5, 0xdb, 0xda, 0x49, 0x6e, 0x1f, 0x30, 0x43,
            0x36, 0x01, 0xed, 0x74,
        ];
        let pk_y = [
            0xf6, 0x39, 0x6f, 0x87, 0xe8, 0xe7, 0x20, 0x55, 0x3d, 0x86, 0x22, 0xa1, 0xbb, 0xd7,
            0xab, 0xf5, 0x01, 0x19, 0x1b, 0xae, 0x74, 0x94, 0x97, 0x86, 0x76, 0x47, 0x6b, 0x00,
            0xfb, 0xd6, 0xda, 0x90,
        ];
        let context = "https://credential-issuer.example.com";
        let nym = generate_nym(&user_sk, &pk_x, &pk_y, context).unwrap();
        assert_eq!(
            nym.to_hex_string(),
            "287a537db35a761cae4b1fecf463088856513c77e5d2c94ddbcf4d85dd0aea18"
        );
    }

    #[test]
    fn test_generate_nym_base64() {
        let user_sk = "deadbeef";
        let pk_x = [
            0xb4, 0x46, 0x2b, 0xe1, 0x47, 0x16, 0x55, 0x9d, 0x26, 0xf1, 0x2e, 0x60, 0x4f, 0xed,
            0xe1, 0x53, 0x39, 0xd2, 0x5a, 0xa4, 0xf5, 0xdb, 0xda, 0x49, 0x6e, 0x1f, 0x30, 0x43,
            0x36, 0x01, 0xed, 0x74,
        ];
        let pk_y = [
            0xf6, 0x39, 0x6f, 0x87, 0xe8, 0xe7, 0x20, 0x55, 0x3d, 0x86, 0x22, 0xa1, 0xbb, 0xd7,
            0xab, 0xf5, 0x01, 0x19, 0x1b, 0xae, 0x74, 0x94, 0x97, 0x86, 0x76, 0x47, 0x6b, 0x00,
            0xfb, 0xd6, 0xda, 0x90,
        ];
        let context = "https://credential-issuer.example.com";
        let nym = generate_nym_base64(user_sk, &pk_x, &pk_y, context).unwrap();
        assert_eq!(nym, "KHpTfbNadhyuSx_s9GMIiFZRPHfl0slN289Nhd0K6hg");
    }

    #[test]
    fn test_commit_attrs() {
        let subject = [
            0x30, 0x29, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x47,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x20, 0x4c, 0x4c, 0x43, 0x31, 0x12, 0x30, 0x10, 0x06,
            0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x44, 0x72, 0x6f, 0x69, 0x64, 0x20, 0x43, 0x41,
            0x33,
        ]; // O=Google LLC, CN=Droid CA3
        let subject_key_identifier = [
            0xfe, 0x62, 0x6c, 0xdc, 0x2a, 0xe5, 0x80, 0xe7, 0x19, 0x6a, 0xca, 0x23, 0xdd, 0x23,
            0xf1, 0x39, 0x02, 0x46, 0xa8, 0xa5,
        ];
        let subject_pk_x = [
            0x29, 0xc2, 0xef, 0x24, 0xa4, 0xbe, 0x89, 0xfd, 0x51, 0x35, 0x89, 0x24, 0xb3, 0x2e,
            0x38, 0xd2, 0x5b, 0x64, 0x9e, 0x4e, 0x96, 0xff, 0x0b, 0x6f, 0x6b, 0xe2, 0x12, 0x87,
            0x1b, 0xf5, 0x26, 0x27,
        ];
        let subject_pk_y = [
            0x9a, 0x9d, 0x6b, 0x56, 0x68, 0x29, 0xbf, 0x3a, 0xf8, 0xfe, 0xe0, 0x50, 0x94, 0x3f,
            0xbb, 0x70, 0xab, 0xf5, 0xb1, 0xb3, 0x5a, 0xc1, 0xe3, 0xb8, 0x95, 0xee, 0x2e, 0xc0,
            0xa8, 0x5a, 0xfb, 0xd2,
        ];

        let CommitResult { cmt_x, cmt_y, r } = commit_attrs(
            &subject,
            &subject_key_identifier,
            &subject_pk_x,
            &subject_pk_y,
            None,
        )
        .unwrap();
        assert_eq!(cmt_x.len(), 64); // 32 bytes in hex
        assert_eq!(cmt_y.len(), 64); // 32 bytes in hex
        assert_eq!(r.len(), 64); // 32 bytes in hex
    }

    #[test]
    fn test_commit_attrs_with_given_randomness() {
        let subject = [
            0x30, 0x29, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x47,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x20, 0x4c, 0x4c, 0x43, 0x31, 0x12, 0x30, 0x10, 0x06,
            0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x44, 0x72, 0x6f, 0x69, 0x64, 0x20, 0x43, 0x41,
            0x33,
        ]; // O=Google LLC, CN=Droid CA3
        let subject_key_identifier = [
            0xfe, 0x62, 0x6c, 0xdc, 0x2a, 0xe5, 0x80, 0xe7, 0x19, 0x6a, 0xca, 0x23, 0xdd, 0x23,
            0xf1, 0x39, 0x02, 0x46, 0xa8, 0xa5,
        ];
        let subject_pk_x = [
            0x29, 0xc2, 0xef, 0x24, 0xa4, 0xbe, 0x89, 0xfd, 0x51, 0x35, 0x89, 0x24, 0xb3, 0x2e,
            0x38, 0xd2, 0x5b, 0x64, 0x9e, 0x4e, 0x96, 0xff, 0x0b, 0x6f, 0x6b, 0xe2, 0x12, 0x87,
            0x1b, 0xf5, 0x26, 0x27,
        ];
        let subject_pk_y = [
            0x9a, 0x9d, 0x6b, 0x56, 0x68, 0x29, 0xbf, 0x3a, 0xf8, 0xfe, 0xe0, 0x50, 0x94, 0x3f,
            0xbb, 0x70, 0xab, 0xf5, 0xb1, 0xb3, 0x5a, 0xc1, 0xe3, 0xb8, 0x95, 0xee, 0x2e, 0xc0,
            0xa8, 0x5a, 0xfb, 0xd2,
        ];
        let r = "deadbeef";

        let CommitResult { cmt_x, cmt_y, r } = commit_attrs(
            &subject,
            &subject_key_identifier,
            &subject_pk_x,
            &subject_pk_y,
            Some(r),
        )
        .unwrap();
        assert_eq!(cmt_x.len(), 64); // 32 bytes in hex
        assert_eq!(cmt_y.len(), 64); // 32 bytes in hex
        assert_eq!(r.len(), 64); // 32 bytes in hex
        assert_eq!(
            cmt_x,
            "06c54c7142201e07095430f7e9d69848e525c93c56958b22054d13f4fd98a41e"
        );
        assert_eq!(
            cmt_y,
            "0850beb53a88e53106894548cc0a40b5f8d8383679628f0a12437bec500f6483"
        );
    }

    #[test]
    #[serial]
    fn test_prove_es256_ca() {
        let version = "0.2.0";

        let meta = CircuitMeta::new(
            format!("es256_ca/{version}"),
            format!("data/es256_ca/{version}/circuit.json"),
            format!("data/es256_ca/{version}/vk"),
            format!("data/es256_ca/{version}/keccak.vk"),
            "data/default_20.srs".to_string(),
        );
        let cert = std::fs::read("test_data/strongbox.der").unwrap();

        let now = 1757808000; // 2025-09-14T00:00:00Z

        // Generate previous commitment
        let issuer = [
            0x30, 0x29, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x47,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x20, 0x4c, 0x4c, 0x43, 0x31, 0x12, 0x30, 0x10, 0x06,
            0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x44, 0x72, 0x6f, 0x69, 0x64, 0x20, 0x43, 0x41,
            0x33,
        ]; // O=Google LLC, CN=Droid CA3        
        let authority_key_id = [
            0xfe, 0x62, 0x6c, 0xdc, 0x2a, 0xe5, 0x80, 0xe7, 0x19, 0x6a, 0xca, 0x23, 0xdd, 0x23,
            0xf1, 0x39, 0x02, 0x46, 0xa8, 0xa5,
        ];
        let issuer_pk_x = [
            0x29, 0xc2, 0xef, 0x24, 0xa4, 0xbe, 0x89, 0xfd, 0x51, 0x35, 0x89, 0x24, 0xb3, 0x2e,
            0x38, 0xd2, 0x5b, 0x64, 0x9e, 0x4e, 0x96, 0xff, 0x0b, 0x6f, 0x6b, 0xe2, 0x12, 0x87,
            0x1b, 0xf5, 0x26, 0x27,
        ];
        let issuer_pk_y = [
            0x9a, 0x9d, 0x6b, 0x56, 0x68, 0x29, 0xbf, 0x3a, 0xf8, 0xfe, 0xe0, 0x50, 0x94, 0x3f,
            0xbb, 0x70, 0xab, 0xf5, 0xb1, 0xb3, 0x5a, 0xc1, 0xe3, 0xb8, 0x95, 0xee, 0x2e, 0xc0,
            0xa8, 0x5a, 0xfb, 0xd2,
        ];
        let prev_cmt_r = "deadbeef";
        let CommitResult {
            cmt_x: prev_cmt_x,
            cmt_y: prev_cmt_y,
            r: _,
        } = commit_attrs(
            &issuer,
            &authority_key_id,
            &issuer_pk_x,
            &issuer_pk_y,
            Some(prev_cmt_r),
        )
        .unwrap();

        // Generate proof
        let CAProofResult {
            proof_with_public_inputs,
            next_cmt_x,
            next_cmt_y,
            next_cmt_r,
        } = prove_ca(
            &meta,
            &cert,
            Some(now),
            &issuer_pk_x,
            &issuer_pk_y,
            &prev_cmt_x,
            &prev_cmt_y,
            &prev_cmt_r.to_string(),
            false,
        )
        .unwrap();

        assert!(!proof_with_public_inputs.proof.is_empty());
        assert_eq!(next_cmt_x.len(), 64); // 32 bytes in hex
        assert_eq!(next_cmt_y.len(), 64); // 32 bytes in hex
        assert_eq!(next_cmt_r.len(), 64); // 32 bytes in hex
        assert_eq!(
            proof_with_public_inputs.num_public_inputs,
            11 // Number of public inputs expected for es256_ca
        );

        // Generate next commitment and check it matches
        let subject = [
            0x30, 0x3f, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x20, 0x65,
            0x35, 0x62, 0x66, 0x61, 0x39, 0x37, 0x37, 0x31, 0x35, 0x63, 0x31, 0x63, 0x62, 0x31,
            0x31, 0x37, 0x30, 0x63, 0x33, 0x30, 0x65, 0x30, 0x31, 0x33, 0x33, 0x31, 0x65, 0x65,
            0x66, 0x34, 0x32, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x09,
            0x53, 0x74, 0x72, 0x6f, 0x6e, 0x67, 0x42, 0x6f, 0x78,
        ]; // CN=e5bfa97715c1cb1170c30e01331eef42, O=StrongBox
        let subject_key_id = [
            0x83, 0x29, 0xbe, 0xbb, 0x68, 0xbc, 0x24, 0xed, 0x89, 0x38, 0x4d, 0xb4, 0xf1, 0x94,
            0x6c, 0x20, 0xd7, 0x95, 0x9a, 0x05,
        ];
        let subject_pk_x = [
            0xa3, 0x30, 0xd2, 0x88, 0x45, 0xc2, 0xf4, 0xb1, 0x60, 0xa7, 0xa5, 0xa8, 0xec, 0x1e,
            0x46, 0x21, 0x31, 0x18, 0x5e, 0x25, 0xba, 0x48, 0x7e, 0xba, 0x2f, 0xbb, 0x41, 0xd7,
            0x18, 0xa7, 0xa6, 0xbf,
        ];
        let subject_pk_y = [
            0xd7, 0x87, 0x8d, 0xc6, 0x36, 0xe4, 0x1e, 0xa4, 0xe2, 0x51, 0x6a, 0xa9, 0xc4, 0xf7,
            0x1f, 0xce, 0x15, 0xf5, 0xd2, 0x48, 0x34, 0x05, 0x82, 0x56, 0x99, 0x72, 0x5c, 0xb1,
            0x3c, 0xeb, 0x47, 0xcd,
        ];
        let CommitResult {
            cmt_x: next_cmt_x_generated,
            cmt_y: next_cmt_y_generated,
            r: _,
        } = commit_attrs(
            &subject,
            &subject_key_id,
            &subject_pk_x,
            &subject_pk_y,
            Some(&next_cmt_r),
        )
        .unwrap();
        assert_eq!(next_cmt_x, next_cmt_x_generated);
        assert_eq!(next_cmt_y, next_cmt_y_generated);

        // Generate proof in keccak mode
        let CAProofResult {
            proof_with_public_inputs,
            next_cmt_x,
            next_cmt_y,
            next_cmt_r,
        } = prove_ca(
            &meta,
            &cert,
            Some(now),
            &issuer_pk_x,
            &issuer_pk_y,
            &prev_cmt_x,
            &prev_cmt_y,
            &prev_cmt_r.to_string(),
            true,
        )
        .unwrap();

        assert!(!proof_with_public_inputs.proof.is_empty());
        assert_eq!(next_cmt_x.len(), 64); // 32 bytes in hex
        assert_eq!(next_cmt_y.len(), 64); // 32 bytes in hex
        assert_eq!(next_cmt_r.len(), 64); // 32 bytes in hex
        assert_eq!(
            proof_with_public_inputs.num_public_inputs,
            11 // Number of public inputs expected for es256_ca
        );
    }

    #[test]
    #[serial]
    fn test_prove_es256_ee() {
        let version = "0.2.0";

        let meta = CircuitMeta::new(
            format!("es256_ee/{version}"),
            format!("data/es256_ee/{version}/circuit.json"),
            format!("data/es256_ee/{version}/vk"),
            format!("data/es256_ee/{version}/keccak.vk"),
            "data/default_20.srs".to_string(),
        );
        let cert = std::fs::read("test_data/keystore.der").unwrap();

        let now = 1757808000; // 2025-09-14T00:00:00Z
        let user_sk = "deadbeef";
        let context = "https://credential-issuer.example.com";

        // Generate previous commitment
        let issuer = vec![
            0x30, 0x3f, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x20, 0x65,
            0x35, 0x62, 0x66, 0x61, 0x39, 0x37, 0x37, 0x31, 0x35, 0x63, 0x31, 0x63, 0x62, 0x31,
            0x31, 0x37, 0x30, 0x63, 0x33, 0x30, 0x65, 0x30, 0x31, 0x33, 0x33, 0x31, 0x65, 0x65,
            0x66, 0x34, 0x32, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x09,
            0x53, 0x74, 0x72, 0x6f, 0x6e, 0x67, 0x42, 0x6f, 0x78,
        ]; // CN=e5bfa97715c1cb1170c30e01331eef42, O=StrongBox
        let authority_key_id = vec![
            0x83, 0x29, 0xbe, 0xbb, 0x68, 0xbc, 0x24, 0xed, 0x89, 0x38, 0x4d, 0xb4, 0xf1, 0x94,
            0x6c, 0x20, 0xd7, 0x95, 0x9a, 0x05,
        ];
        let issuer_pk_x = vec![
            0xa3, 0x30, 0xd2, 0x88, 0x45, 0xc2, 0xf4, 0xb1, 0x60, 0xa7, 0xa5, 0xa8, 0xec, 0x1e,
            0x46, 0x21, 0x31, 0x18, 0x5e, 0x25, 0xba, 0x48, 0x7e, 0xba, 0x2f, 0xbb, 0x41, 0xd7,
            0x18, 0xa7, 0xa6, 0xbf,
        ];
        let issuer_pk_y = vec![
            0xd7, 0x87, 0x8d, 0xc6, 0x36, 0xe4, 0x1e, 0xa4, 0xe2, 0x51, 0x6a, 0xa9, 0xc4, 0xf7,
            0x1f, 0xce, 0x15, 0xf5, 0xd2, 0x48, 0x34, 0x05, 0x82, 0x56, 0x99, 0x72, 0x5c, 0xb1,
            0x3c, 0xeb, 0x47, 0xcd,
        ];
        let prev_cmt_r = "feedface";
        let CommitResult {
            cmt_x: prev_cmt_x,
            cmt_y: prev_cmt_y,
            r: _,
        } = commit_attrs(
            &issuer,
            &authority_key_id,
            &issuer_pk_x,
            &issuer_pk_y,
            Some(prev_cmt_r),
        )
        .unwrap();

        // Generate proof
        let EEProofResult {
            proof_with_public_inputs,
            nym,
        } = prove_ee(
            &meta,
            &cert,
            Some(now),
            &issuer_pk_x,
            &issuer_pk_y,
            &prev_cmt_x,
            &prev_cmt_y,
            &prev_cmt_r.to_string(),
            &authority_key_id,
            user_sk,
            context,
            false,
        )
        .unwrap();

        assert!(!proof_with_public_inputs.proof.is_empty());
        assert_eq!(
            proof_with_public_inputs.num_public_inputs,
            11 // Number of public inputs expected for es256_ca
        );
        assert_eq!(
            nym,
            "KHpTfbNadhyuSx_s9GMIiFZRPHfl0slN289Nhd0K6hg".to_string()
        );

        // Generate proof in keccak mode
        let EEProofResult {
            proof_with_public_inputs,
            nym,
        } = prove_ee(
            &meta,
            &cert,
            Some(now),
            &issuer_pk_x,
            &issuer_pk_y,
            &prev_cmt_x,
            &prev_cmt_y,
            &prev_cmt_r.to_string(),
            &authority_key_id,
            user_sk,
            context,
            true,
        )
        .unwrap();

        assert!(!proof_with_public_inputs.proof.is_empty());
        assert_eq!(
            proof_with_public_inputs.num_public_inputs,
            11 // Number of public inputs expected for es256_ca
        );
        assert_eq!(
            nym,
            "KHpTfbNadhyuSx_s9GMIiFZRPHfl0slN289Nhd0K6hg".to_string()
        );
    }

    #[test]
    #[serial]
    fn test_prove_es256_chain_ca_ee_b64() {
        let version = "0.2.0";

        let meta_subroot = CircuitMeta::new(
            format!("es256_subroot/{version}"),
            format!("data/es256_subroot/{version}/circuit.json"),
            format!("data/es256_subroot/{version}/vk"),
            format!("data/es256_subroot/{version}/keccak.vk"),
            format!("data/default_20.srs"),
        );
        let meta_ee = CircuitMeta::new(
            format!("es256_ee/{version}"),
            format!("data/es256_ee/{version}/circuit.json"),
            format!("data/es256_ee/{version}/vk"),
            format!("data/es256_ee/{version}/keccak.vk"),
            "data/default_20.srs".to_string(),
        );

        let cert_root = std::fs::read("test_data/droid_ca3.der").unwrap();
        let cert_subroot = std::fs::read("test_data/strongbox.der").unwrap();
        let cert_ee = std::fs::read("test_data/keystore.der").unwrap();

        let now = 1757808000; // 2025-09-14T00:00:00Z
        let user_sk = "deadbeef";
        let context = "https://credential-issuer.example.com";

        let result = prove_chain_base64(
            &meta_subroot,
            &[],
            &meta_ee,
            &cert_root,
            &cert_subroot,
            &[],
            &cert_ee,
            Some(now),
            &user_sk,
            context,
            false,
        )
        .unwrap();

        assert_eq!(result.now, now);
        assert!(!result.nym.is_empty());
        assert!(!result.proofs_and_commitments.is_empty());
    }

    #[test]
    #[serial]
    fn test_prove_es256_chain_ca_ee_key_attestation_jwt() {
        let version = "0.2.0";

        let meta_subroot = CircuitMeta::new(
            format!("es256_subroot/{version}"),
            format!("data/es256_subroot/{version}/circuit.json"),
            format!("data/es256_subroot/{version}/vk"),
            format!("data/es256_subroot/{version}/keccak.vk"),
            format!("data/default_20.srs"),
        );
        let meta_ee = CircuitMeta::new(
            format!("es256_ee/{version}"),
            format!("data/es256_ee/{version}/circuit.json"),
            format!("data/es256_ee/{version}/vk"),
            format!("data/es256_ee/{version}/keccak.vk"),
            "data/default_20.srs".to_string(),
        );

        let cert_root = std::fs::read("test_data/droid_ca3.der").unwrap();
        let cert_subroot = std::fs::read("test_data/strongbox.der").unwrap();
        let cert_ee = std::fs::read("test_data/keystore.der").unwrap();

        let now = 1757808000; // 2025-09-14T00:00:00Z
        let user_sk = "deadbeef";
        let context = "https://credential-issuer.example.com";

        let result = prove_chain_as_key_attestation_jwt(
            &meta_subroot,
            &[],
            &meta_ee,
            &cert_root,
            &cert_subroot,
            &[],
            &cert_ee,
            Some(now),
            &user_sk,
            context,
            false,
        )
        .unwrap();
        assert!(!result.is_empty());

        let header_b64 = result.split('.').next().unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
        let expected_header = format!(
            "{{\"alg\":\"ANASTASIA-AKA\",\"typ\":\"key-attestation+jwt\",\"x5c\":[\"es256_ee/{version}\",\"es256_subroot/{version}\",\"MIIB1jCCAV2gAwIBAgIUAKPaleRujkV60qOYNtfCM5xBWw8wCgYIKoZIzj0EAwMwKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EyMB4XDTI1MDgyMjE2MjM0NloXDTI1MTAzMTE2MjM0NVowKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKcLvJKS+if1RNYkksy440ltknk6W/wtva+IShxv1JieanWtWaCm/Ovj+4FCUP7twq/Wxs1rB47iV7i7AqFr70qNjMGEwDgYDVR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFP5ibNwq5YDnGWrKI90j8TkCRqilMB8GA1UdIwQYMBaAFLv4Nq2Jrmzi5Z6U8NWy19J65HxBMAoGCCqGSM49BAMDA2cAMGQCMAF1II8ktm7BKU6mvr0sh7hL4sbU/3cDI80eIpiC32RYUA1dKPDNGxw5YFrhGQ/yaQIwV/5uJxy0dvZVx2GWfHKWDghfSNmIeeJ5dpPkIaDinCUAGoR0k70+xyBjdzH1K3yY\"]}}"
        );
        assert_eq!(String::from_utf8_lossy(&header_bytes), expected_header);

        // Generate proof in keccak mode
        let result = prove_chain_as_key_attestation_jwt(
            &meta_subroot,
            &[],
            &meta_ee,
            &cert_root,
            &cert_subroot,
            &[],
            &cert_ee,
            Some(now),
            &user_sk,
            context,
            true,
        )
        .unwrap();
        assert!(!result.is_empty());
        assert_eq!(String::from_utf8_lossy(&header_bytes), expected_header);
    }

    #[test]
    #[serial]
    fn test_prove_es384_256_chain_b64() {
        let version = "0.2.0";
        let version_subroot = "0.1.0";

        let meta_subroot = CircuitMeta::new(
            format!("es384_subroot/{version_subroot}"),
            format!("data/es384_subroot/{version_subroot}/circuit.json"),
            format!("data/es384_subroot/{version_subroot}/vk"),
            format!("data/es384_subroot/{version_subroot}/keccak.vk"),
            format!("data/default_20.srs"),
        );
        let meta_ca = CircuitMeta::new(
            format!("es256_ca/{version}"),
            format!("data/es256_ca/{version}/circuit.json"),
            format!("data/es256_ca/{version}/vk"),
            format!("data/es256_ca/{version}/keccak.vk"),
            format!("data/default_20.srs"),
        );
        let meta_ee = CircuitMeta::new(
            format!("es256_ee/{version}"),
            format!("data/es256_ee/{version}/circuit.json"),
            format!("data/es256_ee/{version}/vk"),
            format!("data/es256_ee/{version}/keccak.vk"),
            "data/default_20.srs".to_string(),
        );

        let cert_root = std::fs::read("test_data/droid_ca2.der").unwrap();
        let cert_subroot = std::fs::read("test_data/droid_ca3.der").unwrap();
        let cert_ca = std::fs::read("test_data/strongbox.der").unwrap();
        let cert_ee = std::fs::read("test_data/keystore.der").unwrap();

        let now = 1757808000; // 2025-09-14T00:00:00Z
        let user_sk = "deadbeef";
        let context = "https://credential-issuer.example.com";

        let result = prove_chain_base64(
            &meta_subroot,
            &[meta_ca],
            &meta_ee,
            &cert_root,
            &cert_subroot,
            &[&cert_ca],
            &cert_ee,
            Some(now),
            &user_sk,
            context,
            false,
        )
        .unwrap();

        assert_eq!(result.now, now);
        assert!(!result.nym.is_empty());
        assert!(!result.proofs_and_commitments.is_empty());
    }
}
