use es_common::{
    models::{prepare_serial_number, prepare_subject_public_key_info_es256, prepare_validity},
    utils::UtcTime,
};
use sha256::sha256_var;
use std::ecdsa_secp256r1::verify_signature;

use super::models::{MAX_EXTRA_EXT_LEN, prepare_tbs, SUBJECT_LEN};

pub fn verify(
    issuer_pk_x: [u8; 32],
    issuer_pk_y: [u8; 32],
    sig: [u8; 64],
    serial_number: [u8; 20],
    serial_number_len: u32,
    subject: [u8; SUBJECT_LEN],
    subject_pk_x: [u8; 32],
    subject_pk_y: [u8; 32],
    subject_key_identifier: [u8; 20],
    authority_key_identifier: [u8; 20],
    extra_extension: [u8; MAX_EXTRA_EXT_LEN],
    extra_extension_len: u32,
    not_before: [u8; 7],
    not_after: [u8; 7],
    now: [u8; 7],
) {
    // serial number
    let (serial_number, serial_number_len) =
        prepare_serial_number(serial_number, serial_number_len);

    // validity
    let not_before = UtcTime::from_bytes(not_before);
    let not_after = UtcTime::from_bytes(not_after);
    let now = UtcTime::from_bytes(now);
    let (validity, _validity_len) = prepare_validity(not_before, not_after, now);

    // subject_public_key_info
    let (subject_public_key_info, _subject_public_key_info_len) =
        prepare_subject_public_key_info_es256(subject_pk_x, subject_pk_y);

    // Prepare tbsCertificate
    let (tbs, tbs_len) = prepare_tbs(
        serial_number,
        serial_number_len,
        validity,
        subject,
        subject_public_key_info,
        subject_key_identifier,
        authority_key_identifier,
        extra_extension,
        extra_extension_len,
    );

    // Verify signature
    let hash = sha256_var(tbs, tbs_len as u64);
    let result = verify_signature(issuer_pk_x, issuer_pk_y, sig, hash);
    assert(result, "Signature verification failed");
}
