use chrono::{DateTime, Utc};

use crate::circuit::{Circuit, CircuitMeta};

pub fn prove(
    circuit_meta: &CircuitMeta,
    cert: Vec<u8>,
    now: Option<DateTime<Utc>>,
    authority_key_id: Vec<u8>,
    issuer_pk_x: Vec<u8>,
    issuer_pk_y: Vec<u8>,
    prev_cmt: String,
    prev_cmt_r: String,
) -> Result<(Vec<u8>, String, String), String> {
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
    )?;

    Ok((proof, next_cmt, next_cmt_r))
}
