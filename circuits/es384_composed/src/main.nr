use es256_common::{
    check_nyms, prepare_std_ca_extensions, prepare_std_ee_extensions, verify_es256_256,
};
use es384_common::{prepare_std_ca_extensions as prepare_std_subroot_extensions, verify_es384_256};

global MAX_TBS_LEN: u32 = 500;
global MAX_EXTRA_EXT_LEN: u32 = 30;
global MAX_TBS_LEN_CA: u32 = 500;
global MAX_EXTRA_EXT_LEN_CA: u32 = 30;
global MAX_TBS_LEN_EE: u32 = 700;
global MAX_EXTRA_EXT_LEN_EE: u32 = 500;

fn main(
    // public inputs
    now: pub [u8; 7],
    root_pk_x: pub [u8; 48],
    root_pk_y: pub [u8; 48],
    root: pub [u8; 124],
    root_len: pub u32,
    root_key_identifier: pub [u8; 20],
    context: pub Field,
    nym: pub Field,
    // for subroot
    sig_subroot: [u8; 96],
    serial_number_subroot: [u8; 20],
    serial_number_len_subroot: u32,
    subject_subroot: [u8; 124],
    subject_len_subroot: u32,
    subject_pk_x_subroot: [u8; 32],
    subject_pk_y_subroot: [u8; 32],
    extra_extension_subroot: [u8; MAX_EXTRA_EXT_LEN],
    extra_extension_len_subroot: u32,
    not_before_subroot: [u8; 7],
    not_after_subroot: [u8; 7],
    subject_key_identifier_subroot: [u8; 20],
    subject_key_identifier_index_subroot: u32,
    authority_key_identifier_index_subroot: u32,
    basic_constraints_ca_index_subroot: u32,
    key_usage_key_cert_sign_index_subroot: u32,
    // for ca (assume single intermediate CA)
    sig_ca: [u8; 64],
    serial_number_ca: [u8; 20],
    serial_number_len_ca: u32,
    subject_ca: [u8; 124],
    subject_len_ca: u32,
    subject_pk_x_ca: [u8; 32],
    subject_pk_y_ca: [u8; 32],
    extra_extension_ca: [u8; MAX_EXTRA_EXT_LEN_CA],
    extra_extension_len_ca: u32,
    not_before_ca: [u8; 7],
    not_after_ca: [u8; 7],
    subject_key_identifier_ca: [u8; 20],
    subject_key_identifier_index_ca: u32,
    authority_key_identifier_index_ca: u32,
    basic_constraints_ca_index_ca: u32,
    key_usage_key_cert_sign_index_ca: u32,
    // for ee
    sig_ee: [u8; 64],
    serial_number_ee: [u8; 20],
    serial_number_len_ee: u32,
    subject_ee: [u8; 124],
    subject_len_ee: u32,
    subject_pk_x_ee: [u8; 32],
    subject_pk_y_ee: [u8; 32],
    extra_extension_ee: [u8; MAX_EXTRA_EXT_LEN_EE],
    extra_extension_len_ee: u32,
    not_before_ee: [u8; 7],
    not_after_ee: [u8; 7],
    user_sk: Field,
) {
    // Prepare standard extensions
    let (std_extensions, std_extensions_len) = prepare_std_subroot_extensions(
        subject_key_identifier_subroot,
        root_key_identifier,
        subject_key_identifier_index_subroot,
        authority_key_identifier_index_subroot,
        basic_constraints_ca_index_subroot,
        key_usage_key_cert_sign_index_subroot,
    );

    // Verify subroot cert
    verify_es384_256::<MAX_TBS_LEN, _, _>(
        root_pk_x,
        root_pk_y,
        sig_subroot,
        serial_number_subroot,
        serial_number_len_subroot,
        root,
        root_len,
        subject_subroot,
        subject_len_subroot,
        subject_pk_x_subroot,
        subject_pk_y_subroot,
        std_extensions,
        std_extensions_len,
        extra_extension_subroot,
        extra_extension_len_subroot,
        not_before_subroot,
        not_after_subroot,
        now,
    );

    // Prepare standard extensions for ca
    let (std_extensions_ca, std_extensions_len_ca) = prepare_std_ca_extensions(
        subject_key_identifier_ca,
        subject_key_identifier_subroot,
        subject_key_identifier_index_ca,
        authority_key_identifier_index_ca,
        basic_constraints_ca_index_ca,
        key_usage_key_cert_sign_index_ca,
    );

    // Verify ca cert
    verify_es256_256::<MAX_TBS_LEN_CA, _, _>(
        subject_pk_x_subroot,
        subject_pk_y_subroot,
        sig_ca,
        serial_number_ca,
        serial_number_len_ca,
        subject_subroot,
        subject_len_subroot,
        subject_ca,
        subject_len_ca,
        subject_pk_x_ca,
        subject_pk_y_ca,
        std_extensions_ca,
        std_extensions_len_ca,
        extra_extension_ca,
        extra_extension_len_ca,
        not_before_ca,
        not_after_ca,
        now,
    );

    // Verify pseudonym
    check_nyms(subject_pk_x_ee, subject_pk_y_ee, user_sk, context, nym);

    // Prepare standard extensions
    let (std_extensions_ee, std_extensions_len_ee) = prepare_std_ee_extensions();

    // Verify ee cert
    verify_es256_256::<MAX_TBS_LEN_EE, _, _>(
        subject_pk_x_ca,
        subject_pk_y_ca,
        sig_ee,
        serial_number_ee,
        serial_number_len_ee,
        subject_ca,
        subject_len_ca,
        subject_ee,
        subject_len_ee,
        subject_pk_x_ee,
        subject_pk_y_ee,
        std_extensions_ee,
        std_extensions_len_ee,
        extra_extension_ee,
        extra_extension_len_ee,
        not_before_ee,
        not_after_ee,
        now,
    )
}
