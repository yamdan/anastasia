mod commit;
mod models;
mod verify;

use models::UtcTime;

global MAX_TBS_LEN: u32 = 500;
global MAX_EXTRA_EXT_LEN: u32 = 30;

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
    subject_key_identifier_index: u32,
    authority_key_identifier_index: u32,
    basic_constraints_ca_index: u32,
    key_usage_key_cert_sign_index: u32,
    key_usage_digital_signature_index: u32,
    extra_extension: [u8; MAX_EXTRA_EXT_LEN],
    extra_extension_len: u32,
    notBefore: [u8; 7],
    notAfter: [u8; 7],
    now: pub [u8; 7],
    prev_cmt: pub Field,
    prev_cmt_r: Field,
    next_cmt_r: Field,
) -> pub [Field; 1] {
    let notBefore = UtcTime::from_bytes(notBefore);
    let notAfter = UtcTime::from_bytes(notAfter);
    let now = UtcTime::from_bytes(now);

    verify::verify::<MAX_TBS_LEN, _>(
        issuer_pk_x,
        issuer_pk_y,
        sig,
        serial_number,
        serial_number_len,
        issuer,
        issuer_len,
        notBefore,
        notAfter,
        now,
        subject,
        subject_len,
        subject_pk_x,
        subject_pk_y,
        subject_key_identifier,
        authority_key_identifier,
        subject_key_identifier_index,
        authority_key_identifier_index,
        basic_constraints_ca_index,
        key_usage_key_cert_sign_index,
        key_usage_digital_signature_index,
        extra_extension,
        extra_extension_len,
        prev_cmt,
        prev_cmt_r,
        next_cmt_r,
    )
}
