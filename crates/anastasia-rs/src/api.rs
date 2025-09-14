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
        println!("Proof: {:?}", proof);
        assert!(!proof.is_empty());
        assert_eq!(next_cmt.len(), 64); // 32 bytes in hex
        assert_eq!(next_cmt_r.len(), 64); // 32 bytes in hex        
    }
}
