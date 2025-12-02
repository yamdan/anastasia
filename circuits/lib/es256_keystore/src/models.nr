use es_common::{
    models::{
        key_usage_digital_signature_extension, prepare_subject_public_key_info_es256,
        prepare_validity,
    },
    utils::{encode_length, encode_length_3, UtcTime},
};

global VERSION_LEN: u32 = 5;
global SERIAL_NUMBER_LEN: u32 = 3;
global SIGNATURE_LEN: u32 = 12;
pub global ISSUER_LEN: u32 = 65; // TODO: adjust length
global SUBJECT_LEN: u32 = 33;
global VALIDITY_LEN: u32 = 32;
global SPKI_LEN: u32 = 91;
global MAX_EXT_HEADER_LEN: u32 = 8;
global STD_EXT_LEN: u32 = 16;
pub global MAX_EXTRA_EXT_LEN: u32 = 500;
global MAX_TBS_LEN: u32 = 4
    + VERSION_LEN
    + SERIAL_NUMBER_LEN
    + SIGNATURE_LEN
    + ISSUER_LEN
    + VALIDITY_LEN
    + SUBJECT_LEN
    + SPKI_LEN
    + MAX_EXT_HEADER_LEN
    + STD_EXT_LEN
    + MAX_EXTRA_EXT_LEN;

// Fixed length chunk 0: header, version, serial number, signature, issuer, validity, subject, subject_public_key_info
global FIXED_LEN_CHUNK_0_LEN: u32 = 4
    + VERSION_LEN
    + SERIAL_NUMBER_LEN
    + SIGNATURE_LEN
    + ISSUER_LEN
    + VALIDITY_LEN
    + SUBJECT_LEN
    + SPKI_LEN;

// Variable length chunk 0: extensions header
global VAR_LEN_CHUNK_0_START_LOWER_BOUND: u32 = FIXED_LEN_CHUNK_0_LEN;
global VAR_LEN_CHUNK_0_END_UPPER_BOUND: u32 = FIXED_LEN_CHUNK_0_LEN + MAX_EXT_HEADER_LEN;

// Fixed length chunk 1: standard extensions, extra extension
global FIXED_LEN_CHUNK_1_LEN: u32 = STD_EXT_LEN + MAX_EXTRA_EXT_LEN;

// version = v3
global VERSION: [u8; VERSION_LEN] = [0xa0, 0x03, 0x02, 0x01, 0x02];

// Serial number
global SERIAL_NUMBER: [u8; SERIAL_NUMBER_LEN] = [0x02, 0x01, 0x01];

// signature = ecdsa-with-SHA256
global SIGNATURE: [u8; SIGNATURE_LEN] =
    [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

// subject = "CN=Android Keystore Key"
global SUBJECT: [u8; SUBJECT_LEN] = [
    0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x14, 0x41, 0x6e, 0x64,
    0x72, 0x6f, 0x69, 0x64, 0x20, 0x4b, 0x65, 0x79, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x20, 0x4b, 0x65,
    0x79,
];

pub fn prepare_std_extensions() -> [u8; STD_EXT_LEN] {
    let mut index = 0;
    let mut std_extensions = [0; STD_EXT_LEN];

    let ext = key_usage_digital_signature_extension();
    for j in 0..16 {
        std_extensions[index] = ext[j];
        index += 1;
    }

    assert(index == STD_EXT_LEN, "Standard extensions length mismatch");
    std_extensions
}

pub fn prepare_extensions_header(
    std_extensions_len: u32,
    extra_extension_len: u32,
) -> ([u8; MAX_EXT_HEADER_LEN], u32) {
    let extensions_len = std_extensions_len + extra_extension_len;
    let (extensions_seq_encoded_len, extensions_seq_encoded_len_size) =
        encode_length(extensions_len);
    let (extensions_encoded_len, extensions_encoded_len_size) =
        encode_length(extensions_len + extensions_seq_encoded_len_size + 1);

    let mut index = 0;
    let mut extensions_header = [0; MAX_EXT_HEADER_LEN];
    extensions_header[index] = 0xa3;
    index += 1;
    for i in 0..3 {
        if i < extensions_encoded_len_size {
            extensions_header[index] = extensions_encoded_len[i];
            index += 1;
        }
    }
    extensions_header[index] = 0x30;
    index += 1;
    for i in 0..3 {
        if i < extensions_seq_encoded_len_size {
            extensions_header[index] = extensions_seq_encoded_len[i];
            index += 1;
        }
    }
    let extensions_header_len = index;

    assert(extensions_header_len <= MAX_EXT_HEADER_LEN, "Extensions header length exceeds maximum");

    (extensions_header, extensions_header_len)
}

pub fn reserialize(
    issuer: [u8; ISSUER_LEN],
    subject_pk_x: [u8; 32],
    subject_pk_y: [u8; 32],
    extra_extension: [u8; MAX_EXTRA_EXT_LEN],
    extra_extension_len: u32,
    not_before: [u8; 7],
    not_after: [u8; 7],
    now: [u8; 7],
) -> ([u8; MAX_TBS_LEN], u32) {
    // Prepare validity
    let not_before = UtcTime::from_bytes(not_before);
    let not_after = UtcTime::from_bytes(not_after);
    let now = UtcTime::from_bytes(now);
    let (validity, _validity_len) = prepare_validity(not_before, not_after, now);

    // Prepare subject_public_key_info
    let (subject_public_key_info, _subject_public_key_info_len) =
        prepare_subject_public_key_info_es256(subject_pk_x, subject_pk_y);

    // Prepare extensions header
    let (extensions_header, extensions_header_len) =
        prepare_extensions_header(STD_EXT_LEN, extra_extension_len);

    // Prepare standard extensions
    let std_extensions = prepare_std_extensions();

    // Calculate tbs length
    let tbs_len = 4
        + VERSION_LEN
        + SERIAL_NUMBER_LEN
        + SIGNATURE_LEN
        + ISSUER_LEN
        + VALIDITY_LEN
        + SUBJECT_LEN
        + SPKI_LEN
        + extensions_header_len
        + STD_EXT_LEN
        + extra_extension_len;
    assert(tbs_len <= MAX_TBS_LEN, "tbsCertificate length exceeds MAX_TBS_LEN");
    let tbs_value_len = tbs_len - 4;
    // Assume tbsCertificate length fits in 2 bytes
    assert(tbs_value_len >= 256);
    assert(tbs_value_len <= 65535);
    let tbs_len_bytes = encode_length_3(tbs_value_len);

    // Fixed length chunk 0: header, version, serial number, signature, issuer, validity, subject, subject_public_key_info
    let fixed_len_chunk_0_start = 0;
    let fixed_len_chunk_0_end = fixed_len_chunk_0_start + FIXED_LEN_CHUNK_0_LEN;
    let mut fixed_len_chunk_0_index = 0;
    let mut fixed_len_chunk_0_bytes = [0; FIXED_LEN_CHUNK_0_LEN];
    fixed_len_chunk_0_bytes[0] = 0x30;
    fixed_len_chunk_0_bytes[1] = tbs_len_bytes[0];
    fixed_len_chunk_0_bytes[2] = tbs_len_bytes[1];
    fixed_len_chunk_0_bytes[3] = tbs_len_bytes[2];
    for i in 0..5 {
        fixed_len_chunk_0_bytes[4 + i] = VERSION[i];
    }
    fixed_len_chunk_0_index += 4 + VERSION_LEN;
    // serial number
    for i in 0..SERIAL_NUMBER_LEN {
        fixed_len_chunk_0_bytes[fixed_len_chunk_0_index] = SERIAL_NUMBER[i];
        fixed_len_chunk_0_index += 1;
    }
    // signature
    for i in 0..SIGNATURE_LEN {
        fixed_len_chunk_0_bytes[fixed_len_chunk_0_index] = SIGNATURE[i];
        fixed_len_chunk_0_index += 1;
    }
    // issuer
    for i in 0..ISSUER_LEN {
        fixed_len_chunk_0_bytes[fixed_len_chunk_0_index] = issuer[i];
        fixed_len_chunk_0_index += 1;
    }
    // validity
    for i in 0..VALIDITY_LEN {
        fixed_len_chunk_0_bytes[fixed_len_chunk_0_index] = validity[i];
        fixed_len_chunk_0_index += 1;
    }
    // subject
    for i in 0..SUBJECT_LEN {
        fixed_len_chunk_0_bytes[fixed_len_chunk_0_index] = SUBJECT[i];
        fixed_len_chunk_0_index += 1;
    }
    // subject_public_key_info
    for i in 0..SPKI_LEN {
        fixed_len_chunk_0_bytes[fixed_len_chunk_0_index] = subject_public_key_info[i];
        fixed_len_chunk_0_index += 1;
    }

    // Variable length chunk 0: extensions header
    let var_len_chunk_0_start = fixed_len_chunk_0_end;
    let var_len_chunk_0_end = var_len_chunk_0_start + extensions_header_len;
    let var_len_chunk_0_bytes = extensions_header;
    assert(var_len_chunk_0_start >= VAR_LEN_CHUNK_0_START_LOWER_BOUND);
    assert(var_len_chunk_0_end <= VAR_LEN_CHUNK_0_END_UPPER_BOUND);

    // Fixed length chunk 1: standard extensions, extra extension
    let fixed_len_chunk_1_start = var_len_chunk_0_end;
    let fixed_len_chunk_1_end = fixed_len_chunk_1_start + FIXED_LEN_CHUNK_1_LEN;
    let mut fixed_len_chunk_1_index = 0;
    let mut fixed_len_chunk_1_bytes = [0; FIXED_LEN_CHUNK_1_LEN];
    // standard extensions
    for i in 0..STD_EXT_LEN {
        fixed_len_chunk_1_bytes[fixed_len_chunk_1_index] = std_extensions[i];
        fixed_len_chunk_1_index += 1;
    }
    // extra extension
    for i in 0..MAX_EXTRA_EXT_LEN {
        fixed_len_chunk_1_bytes[fixed_len_chunk_1_index] = if i < extra_extension_len {
            extra_extension[i]
        } else {
            0
        };
        fixed_len_chunk_1_index += 1;
    }

    println("es256_keystore::models::prepare_tbs debug info:");
    println(
        f"VAR_LEN_CHUNK_0_START_LOWER_BOUND: {VAR_LEN_CHUNK_0_START_LOWER_BOUND}, VAR_LEN_CHUNK_0_END_UPPER_BOUND: {VAR_LEN_CHUNK_0_END_UPPER_BOUND}",
    );
    println(
        f"var_len_chunk_0_start: {var_len_chunk_0_start}, var_len_chunk_0_end: {var_len_chunk_0_end}",
    );
    println(
        f"fixed_len_chunk_1_start: {fixed_len_chunk_1_start}, fixed_len_chunk_1_end: {fixed_len_chunk_1_end}",
    );
    println("");

    let mut buf: [u8; MAX_TBS_LEN] = [0; MAX_TBS_LEN];

    for i in 0..VAR_LEN_CHUNK_0_START_LOWER_BOUND {
        let fixed_len_chunk_0_byte = fixed_len_chunk_0_bytes[i - fixed_len_chunk_0_start];

        buf[i] = fixed_len_chunk_0_byte;
    }

    for i in VAR_LEN_CHUNK_0_START_LOWER_BOUND..VAR_LEN_CHUNK_0_END_UPPER_BOUND {
        let in_var_len_chunk_0 = i < fixed_len_chunk_1_start;
        let in_fixed_len_chunk_1 = i >= fixed_len_chunk_1_start & i < fixed_len_chunk_1_end;

        let var_len_chunk_0_byte = if in_var_len_chunk_0 {
            var_len_chunk_0_bytes[i - VAR_LEN_CHUNK_0_START_LOWER_BOUND]
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
