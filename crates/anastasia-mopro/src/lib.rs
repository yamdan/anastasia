// Here we're calling a macro exported with Uniffi. This macro will
// write some functions and bind them to FFI type.
// These functions include:
// - `generate_circom_proof`
// - `verify_circom_proof`
// - `generate_halo2_proof`
// - `verify_halo2_proof`
// - `generate_noir_proof`
// - `verify_noir_proof`
mopro_ffi::app!();

mod ffi_types;

use crate::ffi_types::{
    CAProofResult, ChainProofResultBase64, CircuitMeta, CommitResult, EEProofResult,
};

#[uniffi::export]
fn setup(srs_path: &str) -> Result<(), MoproError> {
    anastasia_rs::setup(srs_path).map_err(|e| MoproError::NoirError(e.to_string()))
}

#[uniffi::export]
fn generate_user_sk() -> String {
    anastasia_rs::generate_user_sk_hex()
}

#[uniffi::export]
fn generate_nym(
    user_sk: &str,
    device_pk_x: &[u8],
    device_pk_y: &[u8],
    context: &str,
) -> Result<String, MoproError> {
    let nym = anastasia_rs::generate_nym_base64(user_sk, device_pk_x, device_pk_y, context)
        .map_err(|e| MoproError::NoirError(e.to_string()))?;
    Ok(nym)
}

#[uniffi::export]
fn commit_attrs(
    subject: Vec<u8>,
    subject_key_identifier: Vec<u8>,
    subject_pk_x: Vec<u8>,
    subject_pk_y: Vec<u8>,
    r: Option<String>,
) -> Result<CommitResult, MoproError> {
    let result = anastasia_rs::commit_attrs(
        &subject,
        &subject_key_identifier,
        &subject_pk_x,
        &subject_pk_y,
        r.as_deref(),
    )
    .map_err(|e| MoproError::NoirError(e.to_string()))?;
    Ok(result.into())
}

#[uniffi::export]
fn prove_ca(
    circuit_meta: CircuitMeta,
    cert: Vec<u8>,
    issuer_pk_x: Vec<u8>,
    issuer_pk_y: Vec<u8>,
    prev_cmt_x: String,
    prev_cmt_y: String,
    prev_cmt_r: String,
    now: Option<i64>,
    is_keccak_mode: Option<bool>,
) -> Result<CAProofResult, MoproError> {
    let proof = anastasia_rs::prove_ca(
        &circuit_meta.into(),
        &cert,
        now,
        &issuer_pk_x,
        &issuer_pk_y,
        &prev_cmt_x,
        &prev_cmt_y,
        &prev_cmt_r,
        is_keccak_mode.unwrap_or(false),
    )
    .map_err(|e| MoproError::NoirError(e.to_string()))?;

    Ok(proof.into())
}

#[uniffi::export]
fn prove_ee(
    circuit_meta: CircuitMeta,
    cert: Vec<u8>,
    issuer_pk_x: Vec<u8>,
    issuer_pk_y: Vec<u8>,
    prev_cmt_x: String,
    prev_cmt_y: String,
    prev_cmt_r: String,
    now: Option<i64>,
    authority_key_id: Vec<u8>,
    user_sk: &str,
    context: &str,
    is_keccak_mode: Option<bool>,
) -> Result<EEProofResult, MoproError> {
    let proof = anastasia_rs::prove_ee(
        &circuit_meta.into(),
        &cert,
        now,
        &issuer_pk_x,
        &issuer_pk_y,
        &prev_cmt_x,
        &prev_cmt_y,
        &prev_cmt_r,
        &authority_key_id,
        user_sk,
        context,
        is_keccak_mode.unwrap_or(false),
    )
    .map_err(|e| MoproError::NoirError(e.to_string()))?;

    Ok(proof.into())
}

#[uniffi::export]
fn prove_chain_base64(
    subroot_circuit_meta: CircuitMeta,
    intermediate_circuits_meta: Vec<CircuitMeta>,
    leaf_circuit_meta: CircuitMeta,
    root_cert: Vec<u8>,
    subroot_cert: Vec<u8>,
    intermediate_certs: Vec<Vec<u8>>,
    leaf_cert: Vec<u8>,
    now: Option<i64>,
    user_sk: &str,
    context: &str,
    is_keccak_mode: Option<bool>,
) -> Result<ChainProofResultBase64, MoproError> {
    let intermediate_circuits_meta_converted: Vec<anastasia_rs::CircuitMeta> =
        intermediate_circuits_meta
            .into_iter()
            .map(|meta| meta.into())
            .collect();

    let intermediate_certs_converted: Vec<&[u8]> = intermediate_certs
        .iter()
        .map(|cert| cert.as_slice())
        .collect();

    let chain_proof = anastasia_rs::prove_chain_base64(
        &subroot_circuit_meta.into(),
        &intermediate_circuits_meta_converted,
        &leaf_circuit_meta.into(),
        &root_cert,
        &subroot_cert,
        &intermediate_certs_converted,
        &leaf_cert,
        now,
        user_sk,
        context,
        is_keccak_mode.unwrap_or(false),
    )
    .map_err(|e| MoproError::NoirError(e.to_string()))?;

    Ok(chain_proof.into())
}

#[uniffi::export]
fn prove_chain_jwt(
    subroot_circuit_meta: CircuitMeta,
    intermediate_circuits_meta: Vec<CircuitMeta>,
    leaf_circuit_meta: CircuitMeta,
    root_cert: Vec<u8>,
    subroot_cert: Vec<u8>,
    intermediate_certs: Vec<Vec<u8>>,
    leaf_cert: Vec<u8>,
    now: Option<i64>,
    user_sk: &str,
    context: &str,
    is_keccak_mode: Option<bool>,
) -> Result<String, MoproError> {
    let intermediate_circuits_meta_converted: Vec<anastasia_rs::CircuitMeta> =
        intermediate_circuits_meta
            .into_iter()
            .map(|meta| meta.into())
            .collect();

    let intermediate_certs_converted: Vec<&[u8]> = intermediate_certs
        .iter()
        .map(|cert| cert.as_slice())
        .collect();

    let chain_proof = anastasia_rs::prove_chain_as_key_attestation_jwt(
        &subroot_circuit_meta.into(),
        &intermediate_circuits_meta_converted,
        &leaf_circuit_meta.into(),
        &root_cert,
        &subroot_cert,
        &intermediate_certs_converted,
        &leaf_cert,
        now,
        user_sk,
        context,
        is_keccak_mode.unwrap_or(false),
    )
    .map_err(|e| MoproError::NoirError(e.to_string()))?;

    Ok(chain_proof)
}

#[uniffi::export]
fn prove_chain_composed_base64(
    circuit_meta: CircuitMeta,
    root_cert: Vec<u8>,
    subroot_cert: Vec<u8>,
    intermediate_certs: Vec<Vec<u8>>,
    leaf_cert: Vec<u8>,
    now: Option<i64>,
    user_sk: &str,
    context: &str,
    is_keccak_mode: Option<bool>,
) -> Result<ChainProofResultBase64, MoproError> {
    let intermediate_certs_converted: Vec<&[u8]> = intermediate_certs
        .iter()
        .map(|cert| cert.as_slice())
        .collect();

    let chain_proof = anastasia_rs::prove_chain_composed_base64(
        &circuit_meta.into(),
        &root_cert,
        &subroot_cert,
        &intermediate_certs_converted,
        &leaf_cert,
        now,
        user_sk,
        context,
        is_keccak_mode.unwrap_or(false),
    )
    .map_err(|e| MoproError::NoirError(e.to_string()))?;

    Ok(chain_proof.into())
}

#[uniffi::export]
fn prove_chain_composed_jwt(
    circuit_meta: CircuitMeta,
    root_cert: Vec<u8>,
    subroot_cert: Vec<u8>,
    intermediate_certs: Vec<Vec<u8>>,
    leaf_cert: Vec<u8>,
    now: Option<i64>,
    user_sk: &str,
    context: &str,
    is_keccak_mode: Option<bool>,
) -> Result<String, MoproError> {
    let intermediate_certs_converted: Vec<&[u8]> = intermediate_certs
        .iter()
        .map(|cert| cert.as_slice())
        .collect();

    let chain_proof = anastasia_rs::prove_chain_composed_as_key_attestation_jwt(
        &circuit_meta.into(),
        &root_cert,
        &subroot_cert,
        &intermediate_certs_converted,
        &leaf_cert,
        now,
        user_sk,
        context,
        is_keccak_mode.unwrap_or(false),
    )
    .map_err(|e| MoproError::NoirError(e.to_string()))?;

    Ok(chain_proof)
}

#[uniffi::export]
fn prove_chain_composed_aka_base64(
    circuit_meta: CircuitMeta,
    root_cert: Vec<u8>,
    subroot_cert: Vec<u8>,
    intermediate_cert: Vec<u8>,
    leaf_cert: Vec<u8>,
    now: Option<i64>,
    user_sk: &str,
    context: &str,
    is_keccak_mode: Option<bool>,
) -> Result<ChainProofResultBase64, MoproError> {
    let chain_proof = anastasia_rs::prove_chain_composed_aka_base64(
        &circuit_meta.into(),
        &root_cert,
        &subroot_cert,
        &intermediate_cert,
        &leaf_cert,
        now,
        user_sk,
        context,
        is_keccak_mode.unwrap_or(false),
    )
    .map_err(|e| MoproError::NoirError(e.to_string()))?;

    Ok(chain_proof.into())
}

#[uniffi::export]
fn prove_chain_composed_aka_jwt(
    circuit_meta: CircuitMeta,
    root_cert: Vec<u8>,
    subroot_cert: Vec<u8>,
    intermediate_cert: Vec<u8>,
    leaf_cert: Vec<u8>,
    now: Option<i64>,
    user_sk: &str,
    context: &str,
    is_keccak_mode: Option<bool>,
) -> Result<String, MoproError> {
    let chain_proof = anastasia_rs::prove_chain_composed_aka_as_key_attestation_jwt(
        &circuit_meta.into(),
        &root_cert,
        &subroot_cert,
        &intermediate_cert,
        &leaf_cert,
        now,
        user_sk,
        context,
        is_keccak_mode.unwrap_or(false),
    )
    .map_err(|e| MoproError::NoirError(e.to_string()))?;

    Ok(chain_proof)
}

#[uniffi::export]
fn generate_pop_tbs_jwt(
    now: Option<i64>,
    nonce: &str,
    context: &str,
    attestation: &str,
) -> Result<String, MoproError> {
    let tbs_jwt =
        anastasia_rs::generate_pop_tbs_as_key_attestation_jwt(now, nonce, context, attestation)
            .map_err(|e| MoproError::NoirError(e.to_string()))?;
    Ok(tbs_jwt)
}

#[uniffi::export]
fn generate_pop_jwt(
    circuit_meta: CircuitMeta,
    device_pk_x: &[u8],
    device_pk_y: &[u8],
    to_be_signed: &str,
    sig: &[u8],
    user_sk: &str,
    context: &str,
    is_keccak_mode: Option<bool>,
) -> Result<String, MoproError> {
    let proof = anastasia_rs::generate_pop_as_key_attestation_jwt(
        &circuit_meta.into(),
        device_pk_x,
        device_pk_y,
        to_be_signed,
        sig,
        user_sk,
        context,
        is_keccak_mode.unwrap_or(false),
    )
    .map_err(|e| MoproError::NoirError(e.to_string()))?;
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    use serial_test::serial;

    #[test]
    fn test_setup() {
        let result = setup("../anastasia-rs/data/default_20.srs");
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_user_sk() {
        let sk = generate_user_sk();
        assert_eq!(sk.len(), 64); // 32 bytes in hex
    }

    #[test]
    fn test_generate_nym() {
        let user_sk = "deadbeef";
        let pk_x = vec![
            0xb4, 0x46, 0x2b, 0xe1, 0x47, 0x16, 0x55, 0x9d, 0x26, 0xf1, 0x2e, 0x60, 0x4f, 0xed,
            0xe1, 0x53, 0x39, 0xd2, 0x5a, 0xa4, 0xf5, 0xdb, 0xda, 0x49, 0x6e, 0x1f, 0x30, 0x43,
            0x36, 0x01, 0xed, 0x74,
        ];
        let pk_y = vec![
            0xf6, 0x39, 0x6f, 0x87, 0xe8, 0xe7, 0x20, 0x55, 0x3d, 0x86, 0x22, 0xa1, 0xbb, 0xd7,
            0xab, 0xf5, 0x01, 0x19, 0x1b, 0xae, 0x74, 0x94, 0x97, 0x86, 0x76, 0x47, 0x6b, 0x00,
            0xfb, 0xd6, 0xda, 0x90,
        ];
        let context = "https://credential-issuer.example.com";
        let nym = generate_nym(user_sk, &pk_x, &pk_y, context).unwrap();
        assert_eq!(nym, "KHpTfbNadhyuSx_s9GMIiFZRPHfl0slN289Nhd0K6hg");
    }

    #[test]
    fn test_commit_attrs() {
        let subject = vec![
            0x30, 0x29, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x47,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x20, 0x4c, 0x4c, 0x43, 0x31, 0x12, 0x30, 0x10, 0x06,
            0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x44, 0x72, 0x6f, 0x69, 0x64, 0x20, 0x43, 0x41,
            0x33,
        ]; // O=Google LLC, CN=Droid CA3
        let subject_key_identifier = vec![
            0xfe, 0x62, 0x6c, 0xdc, 0x2a, 0xe5, 0x80, 0xe7, 0x19, 0x6a, 0xca, 0x23, 0xdd, 0x23,
            0xf1, 0x39, 0x02, 0x46, 0xa8, 0xa5,
        ];
        let subject_pk_x = vec![
            0x29, 0xc2, 0xef, 0x24, 0xa4, 0xbe, 0x89, 0xfd, 0x51, 0x35, 0x89, 0x24, 0xb3, 0x2e,
            0x38, 0xd2, 0x5b, 0x64, 0x9e, 0x4e, 0x96, 0xff, 0x0b, 0x6f, 0x6b, 0xe2, 0x12, 0x87,
            0x1b, 0xf5, 0x26, 0x27,
        ];
        let subject_pk_y = vec![
            0x9a, 0x9d, 0x6b, 0x56, 0x68, 0x29, 0xbf, 0x3a, 0xf8, 0xfe, 0xe0, 0x50, 0x94, 0x3f,
            0xbb, 0x70, 0xab, 0xf5, 0xb1, 0xb3, 0x5a, 0xc1, 0xe3, 0xb8, 0x95, 0xee, 0x2e, 0xc0,
            0xa8, 0x5a, 0xfb, 0xd2,
        ];

        let CommitResult { cmt_x, cmt_y, r } = commit_attrs(
            subject,
            subject_key_identifier,
            subject_pk_x,
            subject_pk_y,
            None,
        )
        .unwrap();
        assert_eq!(cmt_x.len(), 64); // 32 bytes in hex
        assert_eq!(cmt_y.len(), 64); // 32 bytes in hex
        assert_eq!(r.len(), 64); // 32 bytes in hex
    }

    #[test]
    fn test_commit_attrs_with_given_randomness() {
        let subject = vec![
            0x30, 0x29, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x47,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x20, 0x4c, 0x4c, 0x43, 0x31, 0x12, 0x30, 0x10, 0x06,
            0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x44, 0x72, 0x6f, 0x69, 0x64, 0x20, 0x43, 0x41,
            0x33,
        ]; // O=Google LLC, CN=Droid CA3
        let subject_key_identifier = vec![
            0xfe, 0x62, 0x6c, 0xdc, 0x2a, 0xe5, 0x80, 0xe7, 0x19, 0x6a, 0xca, 0x23, 0xdd, 0x23,
            0xf1, 0x39, 0x02, 0x46, 0xa8, 0xa5,
        ];
        let subject_pk_x = vec![
            0x29, 0xc2, 0xef, 0x24, 0xa4, 0xbe, 0x89, 0xfd, 0x51, 0x35, 0x89, 0x24, 0xb3, 0x2e,
            0x38, 0xd2, 0x5b, 0x64, 0x9e, 0x4e, 0x96, 0xff, 0x0b, 0x6f, 0x6b, 0xe2, 0x12, 0x87,
            0x1b, 0xf5, 0x26, 0x27,
        ];
        let subject_pk_y = vec![
            0x9a, 0x9d, 0x6b, 0x56, 0x68, 0x29, 0xbf, 0x3a, 0xf8, 0xfe, 0xe0, 0x50, 0x94, 0x3f,
            0xbb, 0x70, 0xab, 0xf5, 0xb1, 0xb3, 0x5a, 0xc1, 0xe3, 0xb8, 0x95, 0xee, 0x2e, 0xc0,
            0xa8, 0x5a, 0xfb, 0xd2,
        ];
        let r = "deadbeef".to_string();

        let CommitResult { cmt_x, cmt_y, r } = commit_attrs(
            subject,
            subject_key_identifier,
            subject_pk_x,
            subject_pk_y,
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
    fn test_prove_es256_chain_jwt() {
        let version = "0.2.0";

        let meta_subroot = CircuitMeta::new(
            format!("es256_subroot/{version}"),
            format!("../anastasia-rs/data/es256_subroot/{version}/circuit.json"),
            format!("../anastasia-rs/data/es256_subroot/{version}/vk"),
            format!("../anastasia-rs/data/es256_subroot/{version}/keccak.vk"),
            "../anastasia-rs/data/default_20.srs".to_string(),
        );
        let meta_ee = CircuitMeta::new(
            format!("es256_ee/{version}"),
            format!("../anastasia-rs/data/es256_ee/{version}/circuit.json"),
            format!("../anastasia-rs/data/es256_ee/{version}/vk"),
            format!("../anastasia-rs/data/es256_ee/{version}/keccak.vk"),
            "../anastasia-rs/data/default_20.srs".to_string(),
        );

        let cert_root = std::fs::read("../anastasia-rs/test_data/droid_ca3.der").unwrap();
        let cert_subroot = std::fs::read("../anastasia-rs/test_data/strongbox.der").unwrap();
        let cert_ee = std::fs::read("../anastasia-rs/test_data/keystore.der").unwrap();

        setup("../anastasia-rs/data/default_20.srs").unwrap();

        let now = 1763028507; // 2025-11-13T10:08:27Z
        let user_sk = "deadbeef";
        let context = "https://credential-issuer.example.com";

        let result = prove_chain_jwt(
            meta_subroot,
            vec![],
            meta_ee,
            cert_root,
            cert_subroot,
            vec![],
            cert_ee,
            Some(now),
            user_sk,
            context,
            None,
        )
        .unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    #[serial]
    fn test_prove_es256_chain_jwt_keccak_true() {
        let version = "0.2.0";

        let meta_subroot = CircuitMeta::new(
            format!("es256_subroot/{version}"),
            format!("../anastasia-rs/data/es256_subroot/{version}/circuit.json"),
            format!("../anastasia-rs/data/es256_subroot/{version}/vk"),
            format!("../anastasia-rs/data/es256_subroot/{version}/keccak.vk"),
            "../anastasia-rs/data/default_20.srs".to_string(),
        );
        let meta_ee = CircuitMeta::new(
            format!("es256_ee/{version}"),
            format!("../anastasia-rs/data/es256_ee/{version}/circuit.json"),
            format!("../anastasia-rs/data/es256_ee/{version}/vk"),
            format!("../anastasia-rs/data/es256_ee/{version}/keccak.vk"),
            "../anastasia-rs/data/default_20.srs".to_string(),
        );

        let cert_root = std::fs::read("../anastasia-rs/test_data/droid_ca3.der").unwrap();
        let cert_subroot = std::fs::read("../anastasia-rs/test_data/strongbox.der").unwrap();
        let cert_ee = std::fs::read("../anastasia-rs/test_data/keystore.der").unwrap();

        let now = 1763028507; // 2025-11-13T10:08:27Z
        let user_sk = "deadbeef";
        let context = "https://credential-issuer.example.com";

        // keccak mode == true
        let result = prove_chain_jwt(
            meta_subroot,
            vec![],
            meta_ee,
            cert_root,
            cert_subroot,
            vec![],
            cert_ee,
            Some(now),
            user_sk,
            context,
            Some(true),
        )
        .unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    #[serial]
    fn test_prove_es256_chain_jwt_keccak_false() {
        let version = "0.2.0";

        let meta_subroot = CircuitMeta::new(
            format!("es256_subroot/{version}"),
            format!("../anastasia-rs/data/es256_subroot/{version}/circuit.json"),
            format!("../anastasia-rs/data/es256_subroot/{version}/vk"),
            format!("../anastasia-rs/data/es256_subroot/{version}/keccak.vk"),
            "../anastasia-rs/data/default_20.srs".to_string(),
        );
        let meta_ee = CircuitMeta::new(
            format!("es256_ee/{version}"),
            format!("../anastasia-rs/data/es256_ee/{version}/circuit.json"),
            format!("../anastasia-rs/data/es256_ee/{version}/vk"),
            format!("../anastasia-rs/data/es256_ee/{version}/keccak.vk"),
            "../anastasia-rs/data/default_20.srs".to_string(),
        );

        let cert_root = std::fs::read("../anastasia-rs/test_data/droid_ca3.der").unwrap();
        let cert_subroot = std::fs::read("../anastasia-rs/test_data/strongbox.der").unwrap();
        let cert_ee = std::fs::read("../anastasia-rs/test_data/keystore.der").unwrap();

        let now = 1763028507; // 2025-11-13T10:08:27Z
        let user_sk = "deadbeef";
        let context = "https://credential-issuer.example.com";

        // keccak mode == true
        let result = prove_chain_jwt(
            meta_subroot,
            vec![],
            meta_ee,
            cert_root,
            cert_subroot,
            vec![],
            cert_ee,
            Some(now),
            user_sk,
            context,
            Some(false),
        )
        .unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    #[serial]
    fn test_prove_es384_256_chain_jwt_keccak_false() {
        let version = "0.2.0";
        let version_subroot = "0.1.0";

        let meta_subroot = CircuitMeta::new(
            format!("es384_subroot/{version_subroot}"),
            format!("../anastasia-rs/data/es384_subroot/{version_subroot}/circuit.json"),
            format!("../anastasia-rs/data/es384_subroot/{version_subroot}/vk"),
            format!("../anastasia-rs/data/es384_subroot/{version_subroot}/keccak.vk"),
            "../anastasia-rs/data/default_20.srs".to_string(),
        );
        let meta_ca = CircuitMeta::new(
            format!("es256_ca/{version}"),
            format!("../anastasia-rs/data/es256_ca/{version}/circuit.json"),
            format!("../anastasia-rs/data/es256_ca/{version}/vk"),
            format!("../anastasia-rs/data/es256_ca/{version}/keccak.vk"),
            "../anastasia-rs/data/default_20.srs".to_string(),
        );
        let meta_ee = CircuitMeta::new(
            format!("es256_ee/{version}"),
            format!("../anastasia-rs/data/es256_ee/{version}/circuit.json"),
            format!("../anastasia-rs/data/es256_ee/{version}/vk"),
            format!("../anastasia-rs/data/es256_ee/{version}/keccak.vk"),
            "../anastasia-rs/data/default_20.srs".to_string(),
        );

        let cert_root = std::fs::read("../anastasia-rs/test_data/droid_ca2.der").unwrap();
        let cert_subroot = std::fs::read("../anastasia-rs/test_data/droid_ca3.der").unwrap();
        let cert_ca = std::fs::read("../anastasia-rs/test_data/strongbox.der").unwrap();
        let cert_ee = std::fs::read("../anastasia-rs/test_data/keystore.der").unwrap();

        let now = 1763028507; // 2025-11-13T10:08:27Z
        let user_sk = "deadbeef";
        let context = "https://credential-issuer.example.com";

        // keccak mode == true
        let result = prove_chain_jwt(
            meta_subroot,
            vec![meta_ca],
            meta_ee,
            cert_root,
            cert_subroot,
            vec![cert_ca],
            cert_ee,
            Some(now),
            user_sk,
            context,
            Some(false),
        )
        .unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    #[serial]
    fn test_prove_es384_256_chain_composed_jwt_keccak_false() {
        let version = "0.1.0";

        let meta = CircuitMeta::new(
            format!("es384_composed/{version}"),
            format!("../anastasia-rs/data/es384_composed/{version}/circuit.json"),
            format!("../anastasia-rs/data/es384_composed/{version}/vk"),
            format!("../anastasia-rs/data/es384_composed/{version}/keccak.vk"),
            "../anastasia-rs/data/default_20.srs".to_string(),
        );

        let cert_root = std::fs::read("../anastasia-rs/test_data/droid_ca2.der").unwrap();
        let cert_subroot = std::fs::read("../anastasia-rs/test_data/droid_ca3.der").unwrap();
        let cert_ca = std::fs::read("../anastasia-rs/test_data/strongbox.der").unwrap();
        let cert_ee = std::fs::read("../anastasia-rs/test_data/keystore.der").unwrap();

        let now = 1763028507; // 2025-11-13T10:08:27Z
        let user_sk = "deadbeef";
        let context = "https://credential-issuer.example.com";

        // keccak mode == true
        let result = prove_chain_composed_jwt(
            meta,
            cert_root,
            cert_subroot,
            vec![cert_ca],
            cert_ee,
            Some(now),
            user_sk,
            context,
            Some(false),
        )
        .unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    #[serial]
    fn test_prove_es384_256_chain_composed_aka_jwt_keccak_false() {
        let version = "0.1.0";

        let meta = CircuitMeta::new(
            format!("es384_composed_aka/{version}"),
            format!("../anastasia-rs/data/es384_composed_aka/{version}/circuit.json"),
            format!("../anastasia-rs/data/es384_composed_aka/{version}/vk"),
            format!("../anastasia-rs/data/es384_composed_aka/{version}/keccak.vk"),
            "../anastasia-rs/data/default_20.srs".to_string(),
        );

        let cert_root = std::fs::read("../anastasia-rs/test_data/droid_ca2.der").unwrap();
        let cert_subroot = std::fs::read("../anastasia-rs/test_data/droid_ca3.der").unwrap();
        let cert_ca = std::fs::read("../anastasia-rs/test_data/strongbox.der").unwrap();
        let cert_ee = std::fs::read("../anastasia-rs/test_data/keystore.der").unwrap();

        let now = 1763028507; // 2025-11-13T10:08:27Z
        let user_sk = "deadbeef";
        let context = "https://credential-issuer.example.com";

        // keccak mode == true
        let result = prove_chain_composed_aka_jwt(
            meta,
            cert_root,
            cert_subroot,
            cert_ca,
            cert_ee,
            Some(now),
            user_sk,
            context,
            Some(false),
        )
        .unwrap();
        assert!(!result.is_empty());
    }

    use nom::AsBytes;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
    use rand_core::OsRng;

    #[test]
    #[serial]
    fn test_generate_pop() {
        let version = "0.1.0";

        let meta = CircuitMeta::new(
            format!("es256_pop/{version}"),
            format!("../anastasia-rs/data/es256_pop/{version}/circuit.json"),
            format!("../anastasia-rs/data/es256_pop/{version}/vk"),
            format!("../anastasia-rs/data/es256_pop/{version}/keccak.vk"),
            format!("../anastasia-rs/data/default_20.srs"),
        );

        let now = 1763028507; // 2025-11-13T10:08:27Z
        let user_sk = "deadbeef";
        let context = "https://credential-issuer.example.com";
        let nonce = "nonce";
        let attestation = "attestation";

        setup("../anastasia-rs/data/default_20.srs").unwrap();

        let tbs = generate_pop_tbs_jwt(Some(now), nonce, context, attestation).unwrap();
        assert!(!tbs.is_empty());

        let signing_key = SigningKey::random(&mut OsRng);
        let signature: Signature = signing_key.sign(tbs.as_bytes());
        let signature = match signature.normalize_s() {
            Some(norm_sig) => norm_sig,
            None => signature,
        }
        .to_vec();

        let verifying_key = VerifyingKey::from(&signing_key);
        let device_pk_bytes = verifying_key.to_encoded_point(false);
        let device_pk_x = device_pk_bytes.x().unwrap().as_bytes().try_into().unwrap();
        let device_pk_y = device_pk_bytes.y().unwrap().as_bytes().try_into().unwrap();

        let proof = generate_pop_jwt(
            meta,
            device_pk_x,
            device_pk_y,
            &tbs,
            &signature,
            &user_sk,
            context,
            None,
        )
        .unwrap();

        assert!(!proof.is_empty());
    }
}
