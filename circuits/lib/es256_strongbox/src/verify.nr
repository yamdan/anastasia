use sha256::sha256_var;
use std::ecdsa_secp256r1::verify_signature;

use super::models::{MAX_EXTRA_EXT_LEN, reserialize, SUBJECT_LEN};

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
    // Re-Serialize
    let (tbs, tbs_len) = reserialize(
        serial_number,
        serial_number_len,
        subject,
        subject_pk_x,
        subject_pk_y,
        subject_key_identifier,
        authority_key_identifier,
        extra_extension,
        extra_extension_len,
        not_before,
        not_after,
        now,
    );

    // Hash
    let hash = sha256_var(tbs, tbs_len as u64);

    // Verify signature
    let result = verify_signature(issuer_pk_x, issuer_pk_y, sig, hash);

    assert(result, "Signature verification failed");
}
