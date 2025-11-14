use es256_common::{
    check_commitments, check_nyms, prepare_std_ca_extensions, prepare_std_ee_extensions,
    verify_es256_256,
};

global MAX_TBS_LEN: u32 = 500;
global MAX_EXTRA_EXT_LEN: u32 = 30;
global MAX_TBS_LEN2: u32 = 700;
global MAX_EXTRA_EXT_LEN2: u32 = 500;

fn main(
    issuer_pk_x: pub [u8; 32],
    issuer_pk_y: pub [u8; 32],
    sig: [u8; 64],
    serial_number: [u8; 20],
    serial_number_len: u32,
    issuer: pub [u8; 124],
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
    next_cmt: pub (Field, Field),
    next_cmt_r: Field,
    subject_key_identifier: [u8; 20],
    authority_key_identifier: pub [u8; 20],
    subject_key_identifier_index: u32,
    authority_key_identifier_index: u32,
    basic_constraints_ca_index: u32,
    key_usage_key_cert_sign_index: u32,
    sig2: [u8; 64],
    serial_number2: [u8; 20],
    serial_number_len2: u32,
    subject2: [u8; 124],
    subject_len2: u32,
    subject_pk_x2: [u8; 32],
    subject_pk_y2: [u8; 32],
    extra_extension2: [u8; MAX_EXTRA_EXT_LEN2],
    extra_extension_len2: u32,
    not_before2: [u8; 7],
    not_after2: [u8; 7],
    user_sk: Field,
    context: pub Field,
    nym: pub Field,
) {
    // Verify next chain commitment
    let mut subject_pk_x_padded = [0; 48];
    for i in 0..32 {
        subject_pk_x_padded[i] = subject_pk_x[i];
    }
    let mut subject_pk_y_padded = [0; 48];
    for i in 0..32 {
        subject_pk_y_padded[i] = subject_pk_y[i];
    }
    check_commitments(
        subject,
        subject_key_identifier,
        subject_pk_x_padded,
        subject_pk_y_padded,
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
    verify_es256_256::<MAX_TBS_LEN, _, _>(
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
    );

    // Verify pseudonym
    check_nyms(subject_pk_x2, subject_pk_y2, user_sk, context, nym);

    // Prepare standard extensions
    let (std_extensions2, std_extensions_len2) = prepare_std_ee_extensions();

    // Verify signature
    verify_es256_256::<MAX_TBS_LEN2, _, _>(
        subject_pk_x,
        subject_pk_y,
        sig2,
        serial_number2,
        serial_number_len2,
        subject,
        subject_len,
        subject2,
        subject_len2,
        subject_pk_x2,
        subject_pk_y2,
        std_extensions2,
        std_extensions_len2,
        extra_extension2,
        extra_extension_len2,
        not_before2,
        not_after2,
        now,
    )
}
