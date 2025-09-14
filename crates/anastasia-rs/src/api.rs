use chrono::{DateTime, Utc};

use crate::circuit::{Circuit, CircuitMeta};

pub struct ProofResult {
    pub proof: Vec<u8>,
    pub next_cmt: String,
    pub next_cmt_r: String,
}

pub fn prove(
    circuit_meta: &CircuitMeta,
    cert: Vec<u8>,
    now: Option<DateTime<Utc>>,
    authority_key_id: Vec<u8>,
    issuer_pk_x: Vec<u8>,
    issuer_pk_y: Vec<u8>,
    prev_cmt: String,
    prev_cmt_r: String,
) -> Result<ProofResult, String> {
    let circuit = Circuit::new(circuit_meta)?;

    let (proof, next_cmt, next_cmt_r) = crate::prove::prove(
        &circuit,
        cert,
        now,
        authority_key_id,
        issuer_pk_x,
        issuer_pk_y,
        prev_cmt,
        prev_cmt_r,
        circuit.max_extra_extension_len,
    )?;

    Ok(ProofResult {
        proof,
        next_cmt,
        next_cmt_r,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prove_es256_ca() {
        let meta = CircuitMeta::new(
            "es256_ca".to_string(),
            "data/es256_ca.json".to_string(),
            "data/es256_ca.vk".to_string(),
            "data/common.srs".to_string(),
        )
        .unwrap();
        let cert = std::fs::read("test_data/es256_ca.der").unwrap();
        println!(
            "cert = [{}];",
            cert.iter()
                .map(|b| format!("0x{:02x}", b))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let now = Some(Utc::now());
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
        let prev_cmt = "0ede28f511104f08069e07986707873be5cbba917f02f02407ad1fdd6838679b";
        let prev_cmt_r = "deadbeef";
        let ProofResult {
            proof,
            next_cmt,
            next_cmt_r,
        } = prove(
            &meta,
            cert,
            now,
            authority_key_id,
            issuer_pk_x,
            issuer_pk_y,
            prev_cmt.to_string(),
            prev_cmt_r.to_string(),
        )
        .unwrap();

        println!("Next commitment: {}", next_cmt);
        println!("Next commitment randomness: {}", next_cmt_r);
        println!("Proof (hex): {}", hex::encode(&proof));
        println!("Proof length: {}", proof.len());
        assert!(!proof.is_empty());
        assert_eq!(next_cmt.len(), 64); // 32 bytes in hex
        assert_eq!(next_cmt_r.len(), 64); // 32 bytes in hex        
    }

    #[test]
    fn test_prove_es256_ee() {
        let meta = CircuitMeta::new(
            "es256_ee".to_string(),
            "data/es256_ee.json".to_string(),
            "data/es256_ee.vk".to_string(),
            "data/common.srs".to_string(),
        )
        .unwrap();
        let cert = std::fs::read("test_data/es256_ee.der").unwrap();
        println!(
            "cert = [{}];",
            cert.iter()
                .map(|b| format!("0x{:02x}", b))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let now = Some(Utc::now());
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
        let prev_cmt = "2a296b0c9a2c8b4c6c56357c632860849f42a4defa6b491b2421a962a3543f5c";
        let prev_cmt_r = "feedface";
        let ProofResult {
            proof,
            next_cmt,
            next_cmt_r,
        } = prove(
            &meta,
            cert,
            now,
            authority_key_id,
            issuer_pk_x,
            issuer_pk_y,
            prev_cmt.to_string(),
            prev_cmt_r.to_string(),
        )
        .unwrap();

        println!("Next commitment: {}", next_cmt);
        println!("Next commitment randomness: {}", next_cmt_r);
        println!("Proof (hex): {}", hex::encode(&proof));
        println!("Proof length: {}", proof.len());
        assert!(!proof.is_empty());
        assert_eq!(next_cmt.len(), 64); // 32 bytes in hex
        assert_eq!(next_cmt_r.len(), 64); // 32 bytes in hex        
    }
}
