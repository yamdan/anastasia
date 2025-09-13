use num_bigint::BigUint;
use x509_parser::der_parser::der::{DerObjectContent, parse_der_sequence};
use x509_parser::prelude::*;

fn extract_ecdsa_der(signature_value: &[u8]) -> Result<Vec<u8>, String> {
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

    // normalize s to low-s form
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
    let s = s_norm.to_bytes_be();

    let mut res = Vec::with_capacity(64);
    res.extend_from_slice(&r);
    res.extend_from_slice(&s);
    Ok(res)
}

#[derive(Debug)]
pub struct ParsedCert {
    pub signature: [u8; 64],
    pub serial_number: [u8; 20],
    pub serial_number_len: u32,
    pub issuer: [u8; 124],
    pub issuer_len: u32,
    pub subject: [u8; 124],
    pub subject_len: u32,
    pub not_before: [u8; 7],
    pub not_after: [u8; 7],
    pub subject_pk_x: [u8; 32],
    pub subject_pk_y: [u8; 32],
    pub subject_key_identifier: [u8; 20],
    pub authority_key_identifier: [u8; 20],
    pub subject_key_identifier_index: u32,
    pub authority_key_identifier_index: u32,
    pub basic_constraints_ca_index: u32,
    pub key_usage_key_cert_sign_index: u32,
    pub key_usage_digital_signature_index: u32,
    pub extra_extension: Vec<u8>,
    pub extra_extension_len: u32,
}

impl ParsedCert {
    pub fn from_der(cert: &[u8]) -> Result<Self, String> {
        let (_, parsed_cert) = X509Certificate::from_der(cert)
            .map_err(|e| format!("Failed to parse certificate: {}", e))?;

        // parse signature value
        let signature_value = parsed_cert.signature_value.as_ref();
        let signature = extract_ecdsa_der(signature_value)
            .map_err(|e| format!("Failed to extract signature value: {e}"))?;

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
        let spki = &parsed_cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data;
        if spki[0] != 0x04 {
            return Err("Only uncompressed EC public key is supported".to_string());
        }
        let spk_x = &spki[1..33];
        let spk_y = &spki[33..65];
        let spki_len = spki.len();

        // parse extensions
        let mut subject_key_identifier: Vec<u8> = Vec::with_capacity(20);
        let mut subject_key_identifier_index = 0;
        let mut authority_key_identifier: Vec<u8> = Vec::with_capacity(20);
        let mut authority_key_identifier_index = 0;
        let mut basic_constraints_ca_index = 0;
        let mut key_usage_key_cert_sign_index = 0;
        let mut key_usage_digital_signature_index = 0;
        let mut extra_extension: Vec<u8> = Vec::new();
        let mut extra_extension_len = 0;
        for (i, ext) in parsed_cert.extensions().iter().enumerate() {
            let ext_oid = &ext.oid;
            match ext.parsed_extension() {
                ParsedExtension::KeyUsage(ku) => {
                    if ku.key_cert_sign() {
                        key_usage_key_cert_sign_index = i + 1;
                    } else if ku.digital_signature() {
                        key_usage_digital_signature_index = i + 1;
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
            signature: signature
                .try_into()
                .map_err(|_| "Signature length is not 64 bytes".to_string())?,
            serial_number: {
                let mut buf = [0u8; 20];
                if serial_number_len > 20 {
                    return Err("Serial number length exceeds 20 bytes".to_string());
                }
                buf[0..serial_number_len].copy_from_slice(serial);
                buf
            },
            serial_number_len: serial_number_len as u32,
            issuer: {
                let mut buf = [0u8; 124];
                if issuer_len > 124 {
                    return Err("Issuer length exceeds 124 bytes".to_string());
                }
                buf[0..issuer_len].copy_from_slice(issuer);
                buf
            },
            issuer_len: issuer_len as u32,
            subject: {
                let mut buf = [0u8; 124];
                if subject_len > 124 {
                    return Err("Subject length exceeds 124 bytes".to_string());
                }
                buf[0..subject_len].copy_from_slice(subject);
                buf
            },
            subject_len: subject_len as u32,
            not_before,
            not_after,
            subject_pk_x: {
                let mut buf = [0u8; 32];
                if spk_x.len() != 32 {
                    return Err("Public key X length is not 32 bytes".to_string());
                }
                buf.copy_from_slice(spk_x);
                buf
            },
            subject_pk_y: {
                let mut buf = [0u8; 32];
                if spk_y.len() != 32 {
                    return Err("Public key Y length is not 32 bytes".to_string());
                }
                buf.copy_from_slice(spk_y);
                buf
            },
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
            key_usage_digital_signature_index: key_usage_digital_signature_index as u32,
            extra_extension,
            extra_extension_len: extra_extension_len as u32,
        })
    }
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
    fn test_parse_es256_ca_cert() {
        let cert = include_bytes!("../test_data/es256_ca.der");
        let parsed_cert = ParsedCert::from_der(cert).unwrap();

        assert_eq!(
            parsed_cert.serial_number,
            [
                0x00, 0xe5, 0xbf, 0xa9, 0x77, 0x15, 0xc1, 0xcb, 0x11, 0x70, 0xc3, 0x0e, 0x01, 0x33,
                0x1e, 0xef, 0x42, 0x00, 0x00, 0x00
            ]
        );
        assert_eq!(parsed_cert.serial_number_len, 17);
        assert_eq!(parsed_cert.not_before, [0x07, 0xe9, 8, 21, 17, 27, 4]);
        assert_eq!(parsed_cert.not_after, [0x07, 0xe9, 9, 16, 15, 20, 10]);
        assert_eq!(
            parsed_cert.issuer,
            [
                0x30, 0x29, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x47,
                0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x20, 0x4c, 0x4c, 0x43, 0x31, 0x12, 0x30, 0x10, 0x06,
                0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x44, 0x72, 0x6f, 0x69, 0x64, 0x20, 0x43, 0x41,
                0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
        assert_eq!(parsed_cert.issuer_len, 43);
        assert_eq!(
            parsed_cert.subject,
            [
                0x30, 0x3f, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x20, 0x65,
                0x35, 0x62, 0x66, 0x61, 0x39, 0x37, 0x37, 0x31, 0x35, 0x63, 0x31, 0x63, 0x62, 0x31,
                0x31, 0x37, 0x30, 0x63, 0x33, 0x30, 0x65, 0x30, 0x31, 0x33, 0x33, 0x31, 0x65, 0x65,
                0x66, 0x34, 0x32, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x09,
                0x53, 0x74, 0x72, 0x6f, 0x6e, 0x67, 0x42, 0x6f, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
        assert_eq!(parsed_cert.subject_len, 65);
        assert_eq!(
            parsed_cert.subject_pk_x,
            [
                0xa3, 0x30, 0xd2, 0x88, 0x45, 0xc2, 0xf4, 0xb1, 0x60, 0xa7, 0xa5, 0xa8, 0xec, 0x1e,
                0x46, 0x21, 0x31, 0x18, 0x5e, 0x25, 0xba, 0x48, 0x7e, 0xba, 0x2f, 0xbb, 0x41, 0xd7,
                0x18, 0xa7, 0xa6, 0xbf
            ]
        );
        assert_eq!(
            parsed_cert.subject_pk_y,
            [
                0xd7, 0x87, 0x8d, 0xc6, 0x36, 0xe4, 0x1e, 0xa4, 0xe2, 0x51, 0x6a, 0xa9, 0xc4, 0xf7,
                0x1f, 0xce, 0x15, 0xf5, 0xd2, 0x48, 0x34, 0x05, 0x82, 0x56, 0x99, 0x72, 0x5c, 0xb1,
                0x3c, 0xeb, 0x47, 0xcd
            ]
        );
        assert_eq!(
            parsed_cert.subject_key_identifier,
            [
                0x83, 0x29, 0xbe, 0xbb, 0x68, 0xbc, 0x24, 0xed, 0x89, 0x38, 0x4d, 0xb4, 0xf1, 0x94,
                0x6c, 0x20, 0xd7, 0x95, 0x9a, 0x05
            ]
        );
        assert_eq!(
            parsed_cert.authority_key_identifier,
            [
                0xfe, 0x62, 0x6c, 0xdc, 0x2a, 0xe5, 0x80, 0xe7, 0x19, 0x6a, 0xca, 0x23, 0xdd, 0x23,
                0xf1, 0x39, 0x02, 0x46, 0xa8, 0xa5
            ]
        );
        assert_eq!(parsed_cert.subject_key_identifier_index, 1);
        assert_eq!(parsed_cert.authority_key_identifier_index, 2);
        assert_eq!(parsed_cert.basic_constraints_ca_index, 3);
        assert_eq!(parsed_cert.key_usage_key_cert_sign_index, 4);
        assert_eq!(parsed_cert.key_usage_digital_signature_index, 0);
        assert_eq!(
            parsed_cert.extra_extension,
            [
                0x30, 0x1a, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x1e,
                0x04, 0x0c, 0xa2, 0x01, 0x18, 0x20, 0x03, 0x66, 0x47, 0x6f, 0x6f, 0x67, 0x6c,
                0x65,
                //                0x00, 0x00
            ]
        );
        assert_eq!(parsed_cert.extra_extension_len, 28);
    }

    #[test]
    fn test_parse_es256_ee_cert() {
        let cert = include_bytes!("../test_data/es256_ee.der");
        let parsed_cert = ParsedCert::from_der(cert).unwrap();

        assert_eq!(
            parsed_cert.serial_number,
            [
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
        assert_eq!(parsed_cert.serial_number_len, 1);
        assert_eq!(parsed_cert.not_before, [0x07, 0xb2, 1, 1, 0, 0, 0]);
        assert_eq!(parsed_cert.not_after, [0x08, 0x00, 1, 1, 0, 0, 0]);
        assert_eq!(
            parsed_cert.issuer,
            [
                0x30, 0x3f, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x20, 0x65,
                0x35, 0x62, 0x66, 0x61, 0x39, 0x37, 0x37, 0x31, 0x35, 0x63, 0x31, 0x63, 0x62, 0x31,
                0x31, 0x37, 0x30, 0x63, 0x33, 0x30, 0x65, 0x30, 0x31, 0x33, 0x33, 0x31, 0x65, 0x65,
                0x66, 0x34, 0x32, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x09,
                0x53, 0x74, 0x72, 0x6f, 0x6e, 0x67, 0x42, 0x6f, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
        assert_eq!(parsed_cert.issuer_len, 65);
        assert_eq!(
            parsed_cert.subject,
            [
                0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x14, 0x41,
                0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x20, 0x4b, 0x65, 0x79, 0x73, 0x74, 0x6f, 0x72,
                0x65, 0x20, 0x4b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
        assert_eq!(parsed_cert.subject_len, 33);
        assert_eq!(
            parsed_cert.subject_pk_x,
            [
                0xb4, 0x46, 0x2b, 0xe1, 0x47, 0x16, 0x55, 0x9d, 0x26, 0xf1, 0x2e, 0x60, 0x4f, 0xed,
                0xe1, 0x53, 0x39, 0xd2, 0x5a, 0xa4, 0xf5, 0xdb, 0xda, 0x49, 0x6e, 0x1f, 0x30, 0x43,
                0x36, 0x01, 0xed, 0x74
            ]
        );
        assert_eq!(
            parsed_cert.subject_pk_y,
            [
                0xf6, 0x39, 0x6f, 0x87, 0xe8, 0xe7, 0x20, 0x55, 0x3d, 0x86, 0x22, 0xa1, 0xbb, 0xd7,
                0xab, 0xf5, 0x01, 0x19, 0x1b, 0xae, 0x74, 0x94, 0x97, 0x86, 0x76, 0x47, 0x6b, 0x00,
                0xfb, 0xd6, 0xda, 0x90
            ]
        );
        assert_eq!(
            parsed_cert.subject_key_identifier,
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
        assert_eq!(
            parsed_cert.authority_key_identifier,
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
        assert_eq!(parsed_cert.subject_key_identifier_index, 0);
        assert_eq!(parsed_cert.authority_key_identifier_index, 0);
        assert_eq!(parsed_cert.basic_constraints_ca_index, 0);
        assert_eq!(parsed_cert.key_usage_key_cert_sign_index, 0);
        assert_eq!(parsed_cert.key_usage_digital_signature_index, 1);
        assert_eq!(
            parsed_cert.extra_extension,
            [
                0x30, 0x82, 0x01, 0x26, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02,
                0x01, 0x11, 0x04, 0x82, 0x01, 0x16, 0x30, 0x82, 0x01, 0x12, 0x02, 0x02, 0x01, 0x2c,
                0x0a, 0x01, 0x02, 0x02, 0x02, 0x01, 0x2c, 0x0a, 0x01, 0x02, 0x04, 0x01, 0x00, 0x04,
                0x00, 0x30, 0x55, 0xbf, 0x85, 0x3d, 0x08, 0x02, 0x06, 0x01, 0x99, 0x03, 0xec, 0x61,
                0xb9, 0xbf, 0x85, 0x45, 0x45, 0x04, 0x43, 0x30, 0x41, 0x31, 0x1b, 0x30, 0x19, 0x04,
                0x14, 0x63, 0x6f, 0x6d, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6d,
                0x6f, 0x70, 0x72, 0x6f, 0x61, 0x70, 0x70, 0x02, 0x01, 0x01, 0x31, 0x22, 0x04, 0x20,
                0xa6, 0xbf, 0xe8, 0xe8, 0x02, 0x9a, 0xff, 0x3b, 0xe3, 0x88, 0xbe, 0xb0, 0x63, 0x71,
                0xcc, 0xdf, 0x94, 0xf8, 0x01, 0xdf, 0x43, 0x3d, 0x76, 0xb7, 0xcb, 0xed, 0xcf, 0x4b,
                0x53, 0x8d, 0xd8, 0x76, 0x30, 0x81, 0xa5, 0xa1, 0x08, 0x31, 0x06, 0x02, 0x01, 0x02,
                0x02, 0x01, 0x03, 0xa2, 0x03, 0x02, 0x01, 0x03, 0xa3, 0x04, 0x02, 0x02, 0x01, 0x00,
                0xa5, 0x05, 0x31, 0x03, 0x02, 0x01, 0x04, 0xaa, 0x03, 0x02, 0x01, 0x01, 0xbf, 0x83,
                0x78, 0x03, 0x02, 0x01, 0x02, 0xbf, 0x85, 0x3e, 0x03, 0x02, 0x01, 0x00, 0xbf, 0x85,
                0x40, 0x4c, 0x30, 0x4a, 0x04, 0x20, 0x33, 0x27, 0xaf, 0x62, 0xd8, 0x4a, 0xb8, 0x97,
                0xaf, 0x25, 0x23, 0xa1, 0x6d, 0xcb, 0x58, 0x01, 0xe6, 0x0c, 0x5d, 0x5b, 0x97, 0xf4,
                0x1c, 0xa1, 0xbd, 0x09, 0x9c, 0x47, 0x84, 0xf7, 0xb7, 0x43, 0x01, 0x01, 0xff, 0x0a,
                0x01, 0x00, 0x04, 0x20, 0xc2, 0x09, 0x50, 0x4f, 0x91, 0x51, 0x45, 0x80, 0x40, 0x2d,
                0x6e, 0xe0, 0xb3, 0x62, 0x7c, 0x76, 0xcd, 0xe3, 0xdb, 0x61, 0x25, 0x80, 0x89, 0xac,
                0xa8, 0x9b, 0x62, 0x19, 0xf3, 0x21, 0x5f, 0x91, 0xbf, 0x85, 0x41, 0x05, 0x02, 0x03,
                0x02, 0x71, 0x00, 0xbf, 0x85, 0x42, 0x05, 0x02, 0x03, 0x03, 0x17, 0x0c, 0xbf, 0x85,
                0x4e, 0x06, 0x02, 0x04, 0x01, 0x35, 0x00, 0xb5, 0xbf, 0x85, 0x4f, 0x06, 0x02, 0x04,
                0x01, 0x35, 0x00, 0xb5,
                //0x00, 0x00
            ]
        );
        assert_eq!(parsed_cert.extra_extension_len, 298);
    }
}
