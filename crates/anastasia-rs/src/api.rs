use crate::circuit::{Circuit, CircuitMeta};

pub fn prove(
    circuit_meta: &CircuitMeta,
    cert: Vec<u8>,
    issuer_pk_x: [u8; 32],
    issuer_pk_y: [u8; 32],
) -> Result<Vec<u8>, String> {
    let circuit = Circuit::new(circuit_meta)?;

//    let parsed_cert = parse_cert(&cert)?;

    Ok(vec![])
}
