use ark_bn254::Fr;
use ark_ff::{PrimeField, UniformRand};
use ark_std::rand::rngs::OsRng;
use chrono::{DateTime, Utc};
use noir::utils::{
    ProofWithPublicInputs, get_num_public_inputs_from_circuit, parse_proof_with_public_inputs,
};

use crate::{
    cert::ParsedCert,
    circuit::{Circuit, CircuitMeta},
    utils::ToHexString,
};

pub struct CommitResult {
    pub cmt_x: String,
    pub cmt_y: String,
    pub r: String,
}

pub fn commit_attrs(
    distinguished_name: &Vec<u8>,
    key_id: &Vec<u8>,
    pk_x: &Vec<u8>,
    pk_y: &Vec<u8>,
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
            let mut padded_dn = distinguished_name.clone();
            if padded_dn.len() > 124 {
                return Err("distinguished name must be at most 124 bytes".to_string());
            }
            padded_dn.resize(124, 0u8);
            padded_dn
                .try_into()
                .map_err(|_| "distinguished name must be at most 124 bytes".to_string())?
        },
        key_id
            .as_slice()
            .try_into()
            .map_err(|_| "key_identifier must be 20 bytes".to_string())?,
        pk_x.as_slice()
            .try_into()
            .map_err(|_| "publickey_x must be 32 bytes".to_string())?,
        pk_y.as_slice()
            .try_into()
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

pub struct ProofResult {
    /// The proof with public inputs
    pub proof_with_public_inputs: ProofWithPublicInputs,
    /// The next commitment x-coordinate
    pub next_cmt_x: String,
    /// The next commitment y-coordinate
    pub next_cmt_y: String,
    /// The random value used for the next commitment
    pub next_cmt_r: String,
}

pub fn prove(
    circuit_meta: &CircuitMeta,
    cert: &Vec<u8>,
    now: &DateTime<Utc>,
    authority_key_id: &Vec<u8>,
    issuer_pk_x: &Vec<u8>,
    issuer_pk_y: &Vec<u8>,
    prev_cmt_x: &String,
    prev_cmt_y: &String,
    prev_cmt_r: &String,
) -> Result<ProofResult, String> {
    let parsed_cert =
        ParsedCert::from_der(&cert).map_err(|e| format!("Failed to parse cert: {}", e))?;

    prove_single(
        circuit_meta,
        &parsed_cert,
        now,
        authority_key_id,
        issuer_pk_x,
        issuer_pk_y,
        prev_cmt_x,
        prev_cmt_y,
        prev_cmt_r,
    )
}

pub fn prove_single(
    circuit_meta: &CircuitMeta,
    parsed_cert: &ParsedCert,
    now: &DateTime<Utc>,
    authority_key_id: &Vec<u8>,
    issuer_pk_x: &Vec<u8>,
    issuer_pk_y: &Vec<u8>,
    prev_cmt_x: &String,
    prev_cmt_y: &String,
    prev_cmt_r: &String,
) -> Result<ProofResult, String> {
    let circuit = Circuit::new(circuit_meta)?;

    let (proof, next_cmt_x, next_cmt_y, next_cmt_r) = crate::prove::prove(
        &circuit,
        parsed_cert,
        now,
        authority_key_id,
        issuer_pk_x,
        issuer_pk_y,
        prev_cmt_x,
        prev_cmt_y,
        prev_cmt_r,
        circuit.max_extra_extension_len,
    )?;

    let num_public_inputs = get_num_public_inputs_from_circuit(&circuit.bytecode).map_err(|e| {
        format!(
            "Failed to get number of public inputs from circuit bytecode: {}",
            e
        )
    })?;

    let parsed_proof = parse_proof_with_public_inputs(&proof, num_public_inputs)
        .map_err(|e| format!("Failed to parse proof with public inputs: {}", e))?;

    Ok(ProofResult {
        proof_with_public_inputs: parsed_proof,
        next_cmt_x,
        next_cmt_y,
        next_cmt_r,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::TimeZone;

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
            "1566ab02692714a5c5c07252b13597c49b80b0b4d78849fb8ff9f0d930c9481c"
        );
        assert_eq!(
            cmt_y,
            "20a10a6b5362161c9412b2a93897e481234834c699c84936459d9c6a30cf2537"
        );
    }

    #[test]
    fn test_prove_es256_ca() {
        let meta = CircuitMeta::new(
            "es256_ca".to_string(),
            "data/es256_ca.json".to_string(),
            "data/es256_ca.vk".to_string(),
            "data/common.srs".to_string(),
        );
        let cert = std::fs::read("test_data/es256_ca.der").unwrap();

        let now = Utc.with_ymd_and_hms(2025, 9, 15, 0, 0, 0).unwrap();

        // Generate previous commitment
        let issuer = vec![
            0x30, 0x29, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x47,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x20, 0x4c, 0x4c, 0x43, 0x31, 0x12, 0x30, 0x10, 0x06,
            0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x44, 0x72, 0x6f, 0x69, 0x64, 0x20, 0x43, 0x41,
            0x33,
        ]; // O=Google LLC, CN=Droid CA3        
        let authority_key_id = vec![
            0xfe, 0x62, 0x6c, 0xdc, 0x2a, 0xe5, 0x80, 0xe7, 0x19, 0x6a, 0xca, 0x23, 0xdd, 0x23,
            0xf1, 0x39, 0x02, 0x46, 0xa8, 0xa5,
        ];
        let issuer_pk_x = vec![
            0x29, 0xc2, 0xef, 0x24, 0xa4, 0xbe, 0x89, 0xfd, 0x51, 0x35, 0x89, 0x24, 0xb3, 0x2e,
            0x38, 0xd2, 0x5b, 0x64, 0x9e, 0x4e, 0x96, 0xff, 0x0b, 0x6f, 0x6b, 0xe2, 0x12, 0x87,
            0x1b, 0xf5, 0x26, 0x27,
        ];
        let issuer_pk_y = vec![
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
        let ProofResult {
            proof_with_public_inputs,
            next_cmt_x,
            next_cmt_y,
            next_cmt_r,
        } = prove(
            &meta,
            &cert,
            &now,
            &authority_key_id,
            &issuer_pk_x,
            &issuer_pk_y,
            &prev_cmt_x,
            &prev_cmt_y,
            &prev_cmt_r.to_string(),
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
        let subject = vec![
            0x30, 0x3f, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x20, 0x65,
            0x35, 0x62, 0x66, 0x61, 0x39, 0x37, 0x37, 0x31, 0x35, 0x63, 0x31, 0x63, 0x62, 0x31,
            0x31, 0x37, 0x30, 0x63, 0x33, 0x30, 0x65, 0x30, 0x31, 0x33, 0x33, 0x31, 0x65, 0x65,
            0x66, 0x34, 0x32, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x09,
            0x53, 0x74, 0x72, 0x6f, 0x6e, 0x67, 0x42, 0x6f, 0x78,
        ]; // CN=e5bfa97715c1cb1170c30e01331eef42, O=StrongBox
        let subject_key_id = vec![
            0x83, 0x29, 0xbe, 0xbb, 0x68, 0xbc, 0x24, 0xed, 0x89, 0x38, 0x4d, 0xb4, 0xf1, 0x94,
            0x6c, 0x20, 0xd7, 0x95, 0x9a, 0x05,
        ];
        let subject_pk_x = vec![
            0xa3, 0x30, 0xd2, 0x88, 0x45, 0xc2, 0xf4, 0xb1, 0x60, 0xa7, 0xa5, 0xa8, 0xec, 0x1e,
            0x46, 0x21, 0x31, 0x18, 0x5e, 0x25, 0xba, 0x48, 0x7e, 0xba, 0x2f, 0xbb, 0x41, 0xd7,
            0x18, 0xa7, 0xa6, 0xbf,
        ];
        let subject_pk_y = vec![
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
    }

    #[test]
    fn test_prove_es256_ee() {
        let meta = CircuitMeta::new(
            "es256_ee".to_string(),
            "data/es256_ee.json".to_string(),
            "data/es256_ee.vk".to_string(),
            "data/common.srs".to_string(),
        );
        let cert = std::fs::read("test_data/es256_ee.der").unwrap();

        let now = Utc.with_ymd_and_hms(2025, 9, 15, 0, 0, 0).unwrap();

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
        let ProofResult {
            proof_with_public_inputs,
            next_cmt_x,
            next_cmt_y,
            next_cmt_r,
        } = prove(
            &meta,
            &cert,
            &now,
            &authority_key_id,
            &issuer_pk_x,
            &issuer_pk_y,
            &prev_cmt_x,
            &prev_cmt_y,
            &prev_cmt_r.to_string(),
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
        let subject = vec![
            0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x14, 0x41,
            0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x20, 0x4b, 0x65, 0x79, 0x73, 0x74, 0x6f, 0x72,
            0x65, 0x20, 0x4b, 0x65, 0x79,
        ]; // CN=Android Keystore Key
        let subject_key_id = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]; // Empty key identifier
        let subject_pk_x = vec![
            0xb4, 0x46, 0x2b, 0xe1, 0x47, 0x16, 0x55, 0x9d, 0x26, 0xf1, 0x2e, 0x60, 0x4f, 0xed,
            0xe1, 0x53, 0x39, 0xd2, 0x5a, 0xa4, 0xf5, 0xdb, 0xda, 0x49, 0x6e, 0x1f, 0x30, 0x43,
            0x36, 0x01, 0xed, 0x74,
        ];
        let subject_pk_y = vec![
            0xf6, 0x39, 0x6f, 0x87, 0xe8, 0xe7, 0x20, 0x55, 0x3d, 0x86, 0x22, 0xa1, 0xbb, 0xd7,
            0xab, 0xf5, 0x01, 0x19, 0x1b, 0xae, 0x74, 0x94, 0x97, 0x86, 0x76, 0x47, 0x6b, 0x00,
            0xfb, 0xd6, 0xda, 0x90,
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
    }
}
