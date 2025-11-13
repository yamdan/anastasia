use num_bigint::BigUint;
use oid_registry::{
    OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_SIG_ECDSA_WITH_SHA256,
    OID_SIG_ECDSA_WITH_SHA384,
};
use x509_parser::asn1_rs::Oid;
use x509_parser::der_parser::der::{DerObjectContent, parse_der_sequence};
use x509_parser::prelude::*;

use crate::utils::to_fixed_array;

#[derive(Debug)]
pub struct ParsedCert<'a> {
    pub algorithm_oid: Oid<'a>,
    pub signature: Vec<u8>,
    pub serial_number: [u8; 20],
    pub serial_number_len: u32,
    pub issuer: [u8; 124],
    pub issuer_len: u32,
    pub not_before: [u8; 7],
    pub not_after: [u8; 7],
    pub subject: [u8; 124],
    pub subject_len: u32,
    pub subject_pk_x: Vec<u8>,
    pub subject_pk_y: Vec<u8>,
    pub subject_key_identifier: [u8; 20],
    pub authority_key_identifier: [u8; 20],
    pub subject_key_identifier_index: u32,
    pub authority_key_identifier_index: u32,
    pub basic_constraints_ca_index: u32,
    pub key_usage_key_cert_sign_index: u32,
    pub extra_extension: Vec<u8>,
    pub extra_extension_len: u32,
}

impl<'a> ParsedCert<'a> {
    pub fn from_der(cert: &'a [u8]) -> Result<Self, String> {
        let (_, parsed_cert) = X509Certificate::from_der(cert)
            .map_err(|e| format!("Failed to parse certificate: {}", e))?;

        // parse algorithm
        let algorithm_oid = parsed_cert.signature_algorithm.oid().to_owned();

        // parse signature value
        let signature_value = parsed_cert.signature_value.as_ref();

        // parse serial number
        let serial = parsed_cert.tbs_certificate.raw_serial();
        let serial_number_len = serial.len();

        // parse issuer
        let issuer = parsed_cert.tbs_certificate.issuer.as_raw();
        let issuer_len = issuer.len();

        // parse subject
        let subject = parsed_cert.tbs_certificate.subject.as_raw();
        let subject_len = subject.len();

        // parse validity
        let validity = &parsed_cert.tbs_certificate.validity;
        let not_before = parse_asn1time(&validity.not_before);
        let not_after = parse_asn1time(&validity.not_after);

        // parse subject public key info
        // TODO: take into account other subject public key types (e.g. RSA)
        let spki = &parsed_cert.tbs_certificate.subject_pki;
        let spk_alg = &spki.algorithm.algorithm;
        if *spk_alg != OID_KEY_TYPE_EC_PUBLIC_KEY {
            return Err(format!(
                "Unsupported subject public key algorithm: {}",
                spk_alg
            ));
        }
        let spk_param = match &spki.algorithm.parameters {
            Some(param) => param,
            None => return Err("Subject public key algorithm parameters are missing".to_string()),
        };
        let spk_param_oid = Oid::try_from(spk_param).map_err(|e| {
            format!(
                "Failed to convert subject public key algorithm parameters to OID: {}",
                e
            )
        })?;
        let spk_len = if spk_param_oid == OID_EC_P256 {
            32
        } else if spk_param_oid == OID_NIST_EC_P384 {
            48
        } else {
            return Err(format!(
                "Unsupported subject public key algorithm: {}",
                spk_alg
            ));
        };

        let spk = &spki.subject_public_key.data;
        if spk[0] != 0x04 {
            return Err("Only uncompressed EC public key is supported".to_string());
        }
        let spk_x = &spk[1..(spk_len + 1)];
        let spk_y = &spk[(spk_len + 1)..(2 * spk_len + 1)];

        // parse extensions
        let mut subject_key_identifier: Vec<u8> = Vec::with_capacity(20);
        let mut subject_key_identifier_index = 0;
        let mut authority_key_identifier: Vec<u8> = Vec::with_capacity(20);
        let mut authority_key_identifier_index = 0;
        let mut basic_constraints_ca_index = 0;
        let mut key_usage_key_cert_sign_index = 0;
        let mut extra_extension: Vec<u8> = Vec::new();
        let mut extra_extension_len = 0;
        for (i, ext) in parsed_cert.extensions().iter().enumerate() {
            match ext.parsed_extension() {
                ParsedExtension::KeyUsage(ku) => {
                    if ku.key_cert_sign() {
                        key_usage_key_cert_sign_index = i + 1;
                    }
                }
                ParsedExtension::BasicConstraints(bc) => {
                    if bc.ca {
                        basic_constraints_ca_index = i + 1;
                    }
                }
                ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    authority_key_identifier = match &aki.key_identifier {
                        Some(key_id) => key_id.0.to_vec(),
                        None => {
                            return Err("AuthorityKeyIdentifier.key_identifier is None".to_string());
                        }
                    };
                    authority_key_identifier_index = i + 1;
                }
                ParsedExtension::SubjectKeyIdentifier(ski) => {
                    subject_key_identifier = ski.0.to_vec();
                    subject_key_identifier_index = i + 1;
                }
                ParsedExtension::UnsupportedExtension { oid } => {
                    let oid_bytes = oid.as_bytes();
                    let oid_len = oid_bytes.len();
                    let oid_len_bytes = serialize_length(oid_len)?;

                    let critical_bytes = match ext.critical {
                        true => vec![0x01, 0x01, 0xff],
                        false => vec![],
                    };
                    let critical_len = critical_bytes.len();

                    let value_bytes = ext.value.to_vec();
                    let value_len = value_bytes.len();
                    let value_len_bytes = serialize_length(value_len)?;

                    let total_len = 1 // tag for OID
                    + oid_len_bytes.len() // length of OID length bytes
                    + oid_len // length of OID
                    + critical_len // length of critical
                    + 1 // tag for OCTET STRING
                    + value_len_bytes.len() // length of value length bytes
                    + value_len; // length of value
                    let total_len_bytes = serialize_length(total_len)?;

                    let mut ext_bytes = Vec::with_capacity(total_len + total_len_bytes.len() + 1);
                    ext_bytes.push(0x30); // SEQUENCE
                    ext_bytes.extend_from_slice(&total_len_bytes);
                    ext_bytes.push(0x06); // OID
                    ext_bytes.extend_from_slice(&oid_len_bytes);
                    ext_bytes.extend_from_slice(oid_bytes);
                    ext_bytes.extend_from_slice(&critical_bytes);
                    ext_bytes.push(0x04); // OCTET STRING
                    ext_bytes.extend_from_slice(&value_len_bytes);
                    ext_bytes.extend_from_slice(&value_bytes);
                    extra_extension_len = ext_bytes.len();
                    extra_extension = ext_bytes;
                }
                _ => {}
            }
        }

        Ok(ParsedCert {
            algorithm_oid,
            signature: signature_value.to_vec(),
            serial_number: {
                let mut buf = [0u8; 20];
                if serial_number_len > 20 {
                    return Err("Serial number length exceeds 20 bytes".to_string());
                }
                buf[0..serial_number_len].copy_from_slice(serial);
                buf
            },
            serial_number_len: serial_number_len as u32,
            issuer: { to_fixed_array::<124>(issuer)? },
            issuer_len: issuer_len as u32,
            not_before,
            not_after,
            subject: { to_fixed_array::<124>(subject)? },
            subject_len: subject_len as u32,
            subject_pk_x: spk_x.to_vec(),
            subject_pk_y: spk_y.to_vec(),
            subject_key_identifier: {
                let mut buf = [0u8; 20];
                if subject_key_identifier.len() != 0 && subject_key_identifier.len() != 20 {
                    return Err("SubjectKeyIdentifier length must be 0 or 20 bytes".to_string());
                }
                if subject_key_identifier.len() == 20 {
                    buf.copy_from_slice(&subject_key_identifier);
                }
                buf
            },
            authority_key_identifier: {
                let mut buf = [0u8; 20];
                if authority_key_identifier.len() != 0 && authority_key_identifier.len() != 20 {
                    return Err("AuthorityKeyIdentifier length must be 0 or 20 bytes".to_string());
                }
                if authority_key_identifier.len() == 20 {
                    buf.copy_from_slice(&authority_key_identifier);
                }
                buf
            },
            subject_key_identifier_index: subject_key_identifier_index as u32,
            authority_key_identifier_index: authority_key_identifier_index as u32,
            basic_constraints_ca_index: basic_constraints_ca_index as u32,
            key_usage_key_cert_sign_index: key_usage_key_cert_sign_index as u32,
            extra_extension,
            extra_extension_len: extra_extension_len as u32,
        })
    }

    pub fn extract_normalized_ecdsa_sig(&self) -> Result<Vec<u8>, String> {
        let (_, seq) =
            parse_der_sequence(&self.signature).map_err(|e| format!("parse error: {e:?}"))?;
        let items = match seq.content {
            DerObjectContent::Sequence(ref v) => v,
            _ => return Err("not a sequence".to_string()),
        };
        if items.len() != 2 {
            return Err("sequence does not have 2 elements".to_string());
        }

        let r_uint = items[0]
            .as_biguint()
            .map_err(|e| format!("Failed to convert r to BigUint: {e}"))?;

        // normalize s to low-s form
        let s_uint = items[1]
            .as_biguint()
            .map_err(|e| format!("Failed to convert s to BigUint: {e}"))?;
        let normalized_s_uint = normalize_s(s_uint, &self.algorithm_oid)?;

        let mut res = Vec::with_capacity(64);
        let r = r_uint.to_bytes_be();
        res.extend_from_slice(&r);
        let s = normalized_s_uint.to_bytes_be();
        res.extend_from_slice(&s);
        Ok(res)
    }
}

pub fn normalize_s(s: BigUint, alg: &Oid) -> Result<BigUint, String> {
    let n = if *alg == OID_SIG_ECDSA_WITH_SHA256 {
        BigUint::parse_bytes(
            b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
            16,
        )
        .ok_or_else(|| "Failed to parse secp256r1 order".to_string())?
    } else if *alg == OID_SIG_ECDSA_WITH_SHA384 {
        BigUint::parse_bytes(
            b"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
            16,
        )
        .ok_or_else(|| "Failed to parse secp384r1 order".to_string())? // TODO: optimize $n$ for secp384r1
    } else {
        return Err("Unsupported algorithm".to_string());
    };
    let n_half: BigUint = &n >> 1;
    if s > n_half { Ok(&n - &s) } else { Ok(s) }
}

pub fn serialize_length(len: usize) -> Result<Vec<u8>, String> {
    let mut len_bytes = Vec::new();
    if len < 128 {
        len_bytes.push(len as u8);
    } else if len < 256 {
        len_bytes.push(0x81);
        len_bytes.push(len as u8);
    } else if len < 65536 {
        len_bytes.push(0x82);
        len_bytes.push((len >> 8) as u8);
        len_bytes.push(len as u8);
    } else {
        // This should be enough for our use case
        return Err("Length too long to serialize".to_string());
    }
    Ok(len_bytes)
}

fn parse_asn1time(dt: &ASN1Time) -> [u8; 7] {
    let datetime = dt.to_datetime();
    let year = datetime.year() as u16;
    let year = year.to_be_bytes();
    let month = datetime.month() as u8;
    let day = datetime.day() as u8;
    let hour = datetime.hour() as u8;
    let minute = datetime.minute() as u8;
    let second = datetime.second() as u8;
    [year[0], year[1], month, day, hour, minute, second]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_s_p256() {
        let s_hex = "f4d6445f925c8040fec5632db1fa35f2f28289bfa79c2025b611f112e20bceed";
        let s = BigUint::parse_bytes(s_hex.as_bytes(), 16).unwrap();
        let normalized_s = normalize_s(s, &OID_SIG_ECDSA_WITH_SHA256).unwrap();
        let expected_s_hex = "b29bb9f6da37fc0013a9cd24e05ca0cca6470edff7b7e5f3da7d9b01a575664";
        let expected_s = BigUint::parse_bytes(expected_s_hex.as_bytes(), 16).unwrap();
        assert_eq!(normalized_s, expected_s);
    }

    #[test]
    fn test_normalize_s_p384() {
        let s_hex = "f4d6445f925c8040fec5632db1fa35f2f28289bfa79c2025b611f112e20bceed8e23018211922df44699ab75f97b42a1";
        let s = BigUint::parse_bytes(s_hex.as_bytes(), 16).unwrap();
        let normalized_s = normalize_s(s, &OID_SIG_ECDSA_WITH_SHA384).unwrap();
        let expected_s_hex = "b29bba06da37fbf013a9cd24e05ca0d0d7d76405863dfda11515c6f122b5ef1c9f70c30371e7986a6526df4d349e6d2";
        let expected_s = BigUint::parse_bytes(expected_s_hex.as_bytes(), 16).unwrap();
        assert_eq!(normalized_s, expected_s);
    }
}
