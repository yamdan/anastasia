use es256_common::{
    models::prepare_std_ca_extensions, utils::check_commitments, verify::verify_signature_es256,
};

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
    extra_extension: [u8; MAX_EXTRA_EXT_LEN],
    extra_extension_len: u32,
    not_before: [u8; 7],
    not_after: [u8; 7],
    now: pub [u8; 7],
    prev_cmt: pub (Field, Field),
    prev_cmt_r: Field,
    next_cmt: pub (Field, Field),
    next_cmt_r: Field,
    subject_key_identifier: [u8; 20],
    authority_key_identifier: [u8; 20],
    subject_key_identifier_index: u32,
    authority_key_identifier_index: u32,
    basic_constraints_ca_index: u32,
    key_usage_key_cert_sign_index: u32,
) {
    // Verify previous chain commitment
    check_commitments(
        issuer,
        authority_key_identifier,
        issuer_pk_x,
        issuer_pk_y,
        prev_cmt,
        prev_cmt_r,
    );

    // Verify next chain commitment
    check_commitments(
        subject,
        subject_key_identifier,
        subject_pk_x,
        subject_pk_y,
        next_cmt,
        next_cmt_r,
    );

    // Prepare standard extensions
    let (std_extensions, std_extensions_len) = prepare_std_ca_extensions(
        subject_key_identifier,
        authority_key_identifier,
        subject_key_identifier_index,
        authority_key_identifier_index,
        basic_constraints_ca_index,
        key_usage_key_cert_sign_index,
    );

    // Verify signature
    verify_signature_es256::<MAX_TBS_LEN, _, _>(
        issuer_pk_x,
        issuer_pk_y,
        sig,
        serial_number,
        serial_number_len,
        issuer,
        issuer_len,
        subject,
        subject_len,
        subject_pk_x,
        subject_pk_y,
        std_extensions,
        std_extensions_len,
        extra_extension,
        extra_extension_len,
        not_before,
        not_after,
        now,
    )
}
