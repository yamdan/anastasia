use es_common::{
    models::{
        authority_key_identifier_extension, basic_constraints_ca_extension,
        key_usage_key_cert_sign_extension, subject_key_identifier_extension,
    },
    utils::{encode_length_1, encode_length_3},
};

global VERSION_LEN: u32 = 5;
global MAX_SERIAL_NUMBER_LEN: u32 = 22;
global SIGNATURE_LEN: u32 = 12;
global ISSUER_LEN: u32 = 43;
global SUBJECT_LEN: u32 = 43;
global VALIDITY_LEN: u32 = 32;
global SPKI_LEN: u32 = 91;
global EXT_HEADER_LEN: u32 = 4;
global STD_EXT_LEN: u32 = 97; // 31 + 33 + 17 + 16
global KEY_IDENTIFIER_LEN: u32 = 20;
global MAX_TBS_LEN: u32 = 4
    + VERSION_LEN
    + MAX_SERIAL_NUMBER_LEN
    + SIGNATURE_LEN
    + ISSUER_LEN
    + VALIDITY_LEN
    + SUBJECT_LEN
    + SPKI_LEN
    + EXT_HEADER_LEN
    + STD_EXT_LEN;

// Fixed length chunk 0: header, version
global FIXED_LEN_CHUNK_0_LEN: u32 = 4 + VERSION_LEN;

// Variable length chunk 0: serial number
global VAR_LEN_CHUNK_0_START_LOWER_BOUND: u32 = FIXED_LEN_CHUNK_0_LEN;
global VAR_LEN_CHUNK_0_END_UPPER_BOUND: u32 = FIXED_LEN_CHUNK_0_LEN + MAX_SERIAL_NUMBER_LEN;

// Fixed length chunk 1: signature, issuer, validity, subject, subject_public_key_info, extensions header, standard extensions, extra extension
global FIXED_LEN_CHUNK_1_LEN: u32 = SIGNATURE_LEN
    + ISSUER_LEN
    + VALIDITY_LEN
    + SUBJECT_LEN
    + SPKI_LEN
    + EXT_HEADER_LEN
    + STD_EXT_LEN;

// version = v3
global VERSION: [u8; VERSION_LEN] = [0xa0, 0x03, 0x02, 0x01, 0x02];

// signature = ecdsa-with-SHA384
global SIGNATURE: [u8; SIGNATURE_LEN] =
    [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];

// issuer = "O=Google LLC, CN=Droid CA2"
global ISSUER: [u8; ISSUER_LEN] = [
    0x30, 0x29, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x47, 0x6f, 0x6f,
    0x67, 0x6c, 0x65, 0x20, 0x4c, 0x4c, 0x43, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x13, 0x09, 0x44, 0x72, 0x6f, 0x69, 0x64, 0x20, 0x43, 0x41, 0x32,
];

// subject = "O=Google LLC, CN=Droid CA3"
global SUBJECT: [u8; SUBJECT_LEN] = [
    0x30, 0x29, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x47, 0x6f, 0x6f,
    0x67, 0x6c, 0x65, 0x20, 0x4c, 0x4c, 0x43, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x13, 0x09, 0x44, 0x72, 0x6f, 0x69, 0x64, 0x20, 0x43, 0x41, 0x33,
];

// Prepare extensions header
global EXTENSIONS_HEADER: [u8; EXT_HEADER_LEN] =
    [0xa3, encode_length_1(STD_EXT_LEN + 2), 0x30, encode_length_1(STD_EXT_LEN)];

pub fn prepare_std_extensions(
    subject_key_identifier: [u8; KEY_IDENTIFIER_LEN],
    authority_key_identifier: [u8; KEY_IDENTIFIER_LEN],
) -> [u8; STD_EXT_LEN] {
    let mut index = 0;
    let mut std_extensions = [0; STD_EXT_LEN];

    let ext = key_usage_key_cert_sign_extension();
    for j in 0..16 {
        std_extensions[index] = ext[j];
        index += 1;
    }
    let ext = basic_constraints_ca_extension();
    for j in 0..17 {
        std_extensions[index] = ext[j];
        index += 1;
    }
    let ext = subject_key_identifier_extension(subject_key_identifier);
    for j in 0..31 {
        std_extensions[index] = ext[j];
        index += 1;
    }
    let ext = authority_key_identifier_extension(authority_key_identifier);
    for j in 0..33 {
        std_extensions[index] = ext[j];
        index += 1;
    }

    assert(index == STD_EXT_LEN, "Standard extensions length mismatch");
    std_extensions
}

pub fn prepare_tbs(
    serial_number: [u8; MAX_SERIAL_NUMBER_LEN],
    serial_number_len: u32,
    validity: [u8; VALIDITY_LEN],
    subject_public_key_info: [u8; SPKI_LEN],
    subject_key_identifier: [u8; KEY_IDENTIFIER_LEN],
    authority_key_identifier: [u8; KEY_IDENTIFIER_LEN],
) -> ([u8; MAX_TBS_LEN], u32) {
    // Prepare standard extensions
    let std_extensions = prepare_std_extensions(subject_key_identifier, authority_key_identifier);

    let tbs_len = 4
        + VERSION_LEN
        + serial_number_len
        + SIGNATURE_LEN
        + ISSUER_LEN
        + VALIDITY_LEN
        + SUBJECT_LEN
        + SPKI_LEN
        + EXT_HEADER_LEN
        + STD_EXT_LEN;
    assert(tbs_len <= MAX_TBS_LEN, "tbsCertificate length exceeds MAX_TBS_LEN");
    let tbs_value_len = tbs_len - 4;
    // Assume tbsCertificate length fits in 2 bytes
    assert(tbs_value_len >= 256);
    let tbs_len_bytes = encode_length_3(tbs_value_len);

    // Fixed length chunk 0: header, version
    let fixed_len_chunk_0_start = 0;
    let fixed_len_chunk_0_end = fixed_len_chunk_0_start + FIXED_LEN_CHUNK_0_LEN;
    let mut fixed_len_chunk_0_bytes = [0; FIXED_LEN_CHUNK_0_LEN];
    fixed_len_chunk_0_bytes[0] = 0x30;
    fixed_len_chunk_0_bytes[1] = tbs_len_bytes[0];
    fixed_len_chunk_0_bytes[2] = tbs_len_bytes[1];
    fixed_len_chunk_0_bytes[3] = tbs_len_bytes[2];
    for i in 0..5 {
        fixed_len_chunk_0_bytes[4 + i] = VERSION[i];
    }

    // Variable length chunk 0: serial number
    let var_len_chunk_0_start = fixed_len_chunk_0_end;
    let var_len_chunk_0_end = var_len_chunk_0_start + serial_number_len;
    assert(var_len_chunk_0_start >= VAR_LEN_CHUNK_0_START_LOWER_BOUND);
    assert(var_len_chunk_0_end <= VAR_LEN_CHUNK_0_END_UPPER_BOUND);

    // Fixed length chunk 1: signature, issuer, validity, subject, subject_public_key_info, extensions header, standard extensions, extra extension
    let fixed_len_chunk_1_start = fixed_len_chunk_0_end + serial_number_len;
    let fixed_len_chunk_1_end = fixed_len_chunk_1_start + FIXED_LEN_CHUNK_1_LEN;
    let mut fixed_len_chunk_1_index = 0;
    let mut fixed_len_chunk_1_bytes = [0; FIXED_LEN_CHUNK_1_LEN];
    // signature
    for i in 0..SIGNATURE_LEN {
        fixed_len_chunk_1_bytes[fixed_len_chunk_1_index] = SIGNATURE[i];
        fixed_len_chunk_1_index += 1;
    }
    // issuer
    for i in 0..ISSUER_LEN {
        fixed_len_chunk_1_bytes[fixed_len_chunk_1_index] = ISSUER[i];
        fixed_len_chunk_1_index += 1;
    }
    // validity
    for i in 0..VALIDITY_LEN {
        fixed_len_chunk_1_bytes[fixed_len_chunk_1_index] = validity[i];
        fixed_len_chunk_1_index += 1;
    }
    // subject
    for i in 0..SUBJECT_LEN {
        fixed_len_chunk_1_bytes[fixed_len_chunk_1_index] = SUBJECT[i];
        fixed_len_chunk_1_index += 1;
    }
    // subject_public_key_info
    for i in 0..SPKI_LEN {
        fixed_len_chunk_1_bytes[fixed_len_chunk_1_index] = subject_public_key_info[i];
        fixed_len_chunk_1_index += 1;
    }
    // extensions header
    for i in 0..EXT_HEADER_LEN {
        fixed_len_chunk_1_bytes[fixed_len_chunk_1_index] = EXTENSIONS_HEADER[i];
        fixed_len_chunk_1_index += 1;
    }
    // standard extensions
    for i in 0..STD_EXT_LEN {
        fixed_len_chunk_1_bytes[fixed_len_chunk_1_index] = std_extensions[i];
        fixed_len_chunk_1_index += 1;
    }

    println(
        f"VAR_LEN_CHUNK_0_START_LOWER_BOUND: {VAR_LEN_CHUNK_0_START_LOWER_BOUND}, VAR_LEN_CHUNK_0_END_UPPER_BOUND: {VAR_LEN_CHUNK_0_END_UPPER_BOUND}",
    );
    println(
        f"var_len_chunk_0_start: {var_len_chunk_0_start}, var_len_chunk_0_end: {var_len_chunk_0_end}",
    );
    println(
        f"fixed_len_chunk_1_start: {fixed_len_chunk_1_start}, fixed_len_chunk_1_end: {fixed_len_chunk_1_end}",
    );

    let mut buf: [u8; MAX_TBS_LEN] = [0; MAX_TBS_LEN];

    for i in 0..VAR_LEN_CHUNK_0_START_LOWER_BOUND {
        let fixed_len_chunk_0_byte = fixed_len_chunk_0_bytes[i - fixed_len_chunk_0_start];

        buf[i] = fixed_len_chunk_0_byte;
    }

    for i in VAR_LEN_CHUNK_0_START_LOWER_BOUND..VAR_LEN_CHUNK_0_END_UPPER_BOUND {
        let in_var_len_chunk_0 = i < fixed_len_chunk_1_start;
        let in_fixed_len_chunk_1 = i >= fixed_len_chunk_1_start & i < fixed_len_chunk_1_end;

        let var_len_chunk_0_byte = if in_var_len_chunk_0 {
            serial_number[i - VAR_LEN_CHUNK_0_START_LOWER_BOUND]
        } else {
            0
        };

        let fixed_len_chunk_1_byte = if in_fixed_len_chunk_1 {
            fixed_len_chunk_1_bytes[i - fixed_len_chunk_1_start]
        } else {
            0
        };

        buf[i] = var_len_chunk_0_byte + fixed_len_chunk_1_byte;
    }

    for i in VAR_LEN_CHUNK_0_END_UPPER_BOUND..MAX_TBS_LEN {
        let fixed_len_chunk_1_byte = fixed_len_chunk_1_bytes[i - fixed_len_chunk_1_start];

        buf[i] = fixed_len_chunk_1_byte;
    }

    (buf, tbs_len)
}
