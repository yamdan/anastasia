use num_bigint::BigUint;
use x509_parser::der_parser::der::{DerObjectContent, parse_der_sequence};
use x509_parser::prelude::*;

fn extract_ecdsa_rs_der(signature_value: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (_, seq) =
        parse_der_sequence(signature_value).map_err(|e| format!("parse error: {e:?}"))?;
    let items = match seq.content {
        DerObjectContent::Sequence(ref v) => v,
        _ => return Err("not a sequence".to_string()),
    };
    if items.len() != 2 {
        return Err("sequence does not have 2 elements".to_string());
    }
    let r = match items[0].content {
        DerObjectContent::Integer(ref data) => {
            let d = data.to_vec();
            if d.len() == 33 && d[0] == 0 {
                d[1..].to_vec()
            } else {
                d
            }
        }
        _ => return Err("first element is not integer".to_string()),
    };

    let s_uint = items[1]
        .as_biguint()
        .map_err(|e| format!("Failed to convert s to BigUint: {e}"))?;
    let n = BigUint::parse_bytes(
        b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        16,
    )
    .ok_or("Failed to parse secp256r1 order")?; // TODO: optimize $n$ for secp256r1
    let n_half = &n >> 1;
    let s_norm = if s_uint > n_half {
        &n - &s_uint
    } else {
        s_uint
    };
    Ok((r, s_norm.to_bytes_be()))
}

pub fn parse_cert(cert: &[u8]) -> Result<(), String> {
    let (_, parsed_cert) = X509Certificate::from_der(cert)
        .map_err(|e| format!("Failed to parse certificate: {}", e))?;

    // parse signature value
    let signature_value = parsed_cert.signature_value.as_ref();
    let (r, s) =
        extract_ecdsa_rs_der(signature_value).map_err(|e| format!("Failed to extract r,s: {e}"))?;
    println!("r: {:x?}", r);
    println!("s: {:x?}", s);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cert() {
        let cert = include_bytes!("../test_data/es256_ca.der");
        assert!(parse_cert(cert).is_ok());
    }
}
