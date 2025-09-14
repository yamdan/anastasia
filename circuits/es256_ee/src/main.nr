use es256_core::{verify, models};

global MAX_TBS_LEN: u32 = 700;
global MAX_EXTRA_EXT_LEN: u32 = 300;

fn main(
    issuer_pk_x: [u8; 32],
    issuer_pk_y: [u8; 32],
    sig: [u8; 64],
    serial_number: [u8; 20],
    serial_number_len: u32,
    issuer: [u8; 124],
    issuer_len: u32,
    subject: [u8; 124],
    subject_len: u32,
    subject_pk_x: [u8; 32],
    subject_pk_y: [u8; 32],
    subject_key_identifier: [u8; 20],
    authority_key_identifier: [u8; 20],
    given_authority_key_identifier: [u8; 20],
    subject_key_identifier_index: u32,
    authority_key_identifier_index: u32,
    basic_constraints_ca_index: u32,
    key_usage_key_cert_sign_index: u32,
    key_usage_digital_signature_index: u32,
    extra_extension: [u8; MAX_EXTRA_EXT_LEN],
    extra_extension_len: u32,
    not_before: [u8; 7],
    not_after: [u8; 7],
    now: pub [u8; 7],
    prev_cmt: pub Field,
    prev_cmt_r: Field,
    next_cmt: pub Field,
    next_cmt_r: Field,
) {
    let not_before = models::UtcTime::from_bytes(not_before);
    let not_after = models::UtcTime::from_bytes(not_after);
    let now = models::UtcTime::from_bytes(now);

    verify::verify::<MAX_TBS_LEN, _>(
        issuer_pk_x,
        issuer_pk_y,
        sig,
        serial_number,
        serial_number_len,
        issuer,
        issuer_len,
        not_before,
        not_after,
        now,
        subject,
        subject_len,
        subject_pk_x,
        subject_pk_y,
        subject_key_identifier,
        authority_key_identifier,
        given_authority_key_identifier,
        subject_key_identifier_index,
        authority_key_identifier_index,
        basic_constraints_ca_index,
        key_usage_key_cert_sign_index,
        key_usage_digital_signature_index,
        extra_extension,
        extra_extension_len,
        prev_cmt,
        prev_cmt_r,
        next_cmt,
        next_cmt_r,
    )
}
