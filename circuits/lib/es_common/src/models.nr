use super::utils::{encode_length, UtcTime};

// RFC 5280, Section 4.1.2.2
// "Given the uniqueness requirements above, serial numbers can be
// expected to contain long integers.  Certificate users MUST be able to
// handle serialNumber values up to 20 octets.  Conforming CAs MUST NOT
// use serialNumber values longer than 20 octets"
global MAX_SERIAL_NUMBER_LEN: u32 = 20;

pub fn prepare_serial_number(
    given_serial_number: [u8; MAX_SERIAL_NUMBER_LEN],
    serial_number_len: u32,
) -> ([u8; MAX_SERIAL_NUMBER_LEN + 2], u32) {
    assert(serial_number_len <= MAX_SERIAL_NUMBER_LEN, "Serial number length exceeds maximum");

    let serial_number_len_bytes: [u8; 1] = (serial_number_len as Field).to_be_bytes();

    let mut serial_number = [0; MAX_SERIAL_NUMBER_LEN + 2];
    serial_number[0] = 0x02; // ASN.1 INTEGER tag
    serial_number[1] = serial_number_len_bytes[0]; // Length of the serial number
    for i in 0..MAX_SERIAL_NUMBER_LEN {
        if i < serial_number_len {
            serial_number[i + 2] = given_serial_number[i];
        }
    }
    (serial_number, serial_number_len + 2)
}

global VALIDITY_LEN: u32 = 32;

pub fn prepare_validity(
    not_before: UtcTime,
    not_after: UtcTime,
    now: UtcTime,
) -> ([u8; VALIDITY_LEN], u32) {
    // Check current datetime
    assert(not_before.isBefore(now));
    assert(now.isBefore(not_after));

    let validity_header = [0x30, 0x1e];
    let validity = validity_header.concat(not_before.to_bytes()).concat(not_after.to_bytes());
    assert(validity.len() == VALIDITY_LEN, "Validity length mismatch");

    (validity, validity.len())
}

global SUBJECT_PUBLIC_KEY_INFO_LEN: u32 = 91;

pub fn prepare_subject_public_key_info_es256(
    subject_pk_x: [u8; 32],
    subject_pk_y: [u8; 32],
) -> ([u8; SUBJECT_PUBLIC_KEY_INFO_LEN], u32) {
    let info_header = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ];
    let key_header = [0x03, 0x42, 0x00, 0x04];

    let subject_public_key_info =
        info_header.concat(key_header).concat(subject_pk_x).concat(subject_pk_y);
    assert(
        subject_public_key_info.len() == SUBJECT_PUBLIC_KEY_INFO_LEN,
        "Subject public key info length mismatch",
    );

    (subject_public_key_info, SUBJECT_PUBLIC_KEY_INFO_LEN)
}

pub fn subject_key_identifier_extension(identifier: [u8; 20]) -> [u8; 31] {
    let header = [0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14];
    header.concat(identifier)
}

pub fn authority_key_identifier_extension(identifier: [u8; 20]) -> [u8; 33] {
    let header = [0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14];
    header.concat(identifier)
}

pub fn basic_constraints_ca_extension() -> [u8; 17] {
    [
        0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01,
        0x01, 0xff,
    ]
}

pub fn key_usage_key_cert_sign_extension() -> [u8; 16] {
    [0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x02, 0x04]
}

pub fn key_usage_digital_signature_extension() -> [u8; 16] {
    [0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80]
}

pub fn prepare_std_ee_extensions() -> ([u8; 16], u32) {
    let ext = key_usage_digital_signature_extension();
    (ext, ext.len())
}

global MAX_STD_CA_EXTENSIONS_LEN: u32 = 97; // 31 + 33 + 17 + 16

pub fn prepare_std_ca_extensions(
    subject_key_identifier: [u8; 20],
    authority_key_identifier: [u8; 20],
    subject_key_identifier_index: u32,
    authority_key_identifier_index: u32,
    basic_constraints_ca_index: u32,
    key_usage_key_cert_sign_index: u32,
) -> ([u8; MAX_STD_CA_EXTENSIONS_LEN], u32) {
    //   check that sum of indices must be 10 and product of indices must be 24
    //   to ensure that the indices are unique and cover all 4 extensions
    assert(
        subject_key_identifier_index
            + authority_key_identifier_index
            + basic_constraints_ca_index
            + key_usage_key_cert_sign_index
            == 10,
        "Sum of standard extension indices must be 10",
    );
    assert(
        subject_key_identifier_index
            * authority_key_identifier_index
            * basic_constraints_ca_index
            * key_usage_key_cert_sign_index
            == 24,
        "Product of standard extension indices must be 24",
    );

    let mut index = 0;
    let mut std_extensions = [0; MAX_STD_CA_EXTENSIONS_LEN];
    for i in 1..5 {
        if i == subject_key_identifier_index {
            let ext = subject_key_identifier_extension(subject_key_identifier);
            for j in 0..31 {
                std_extensions[index] = ext[j];
                index += 1;
            }
        } else if i == authority_key_identifier_index {
            let ext = authority_key_identifier_extension(authority_key_identifier);
            for j in 0..33 {
                std_extensions[index] = ext[j];
                index += 1;
            }
        } else if i == basic_constraints_ca_index {
            let ext = basic_constraints_ca_extension();
            for j in 0..17 {
                std_extensions[index] = ext[j];
                index += 1;
            }
        } else if i == key_usage_key_cert_sign_index {
            let ext = key_usage_key_cert_sign_extension();
            for j in 0..16 {
                std_extensions[index] = ext[j];
                index += 1;
            }
        }
    }
    assert(index == MAX_STD_CA_EXTENSIONS_LEN, "Standard extensions length mismatch");
    (std_extensions, index)
}

pub fn prepare_extensions_header(
    std_extensions_len: u32,
    extra_extension_len: u32,
) -> ([u8; 8], u32) {
    let extensions_len = std_extensions_len + extra_extension_len;
    let (extensions_seq_encoded_len, extensions_seq_encoded_len_size) =
        encode_length(extensions_len);
    let (extensions_encoded_len, extensions_encoded_len_size) =
        encode_length(extensions_len + extensions_seq_encoded_len_size + 1);

    let mut index = 0;
    let mut extensions_header = [0; 8];
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

    assert(extensions_header_len <= 8, "Extensions header length exceeds maximum");

    (extensions_header, extensions_header_len)
}

pub fn prepare_tbs<let MAX_TBS_LEN: u32, let MAX_STD_EXT_LEN: u32, let MAX_EXTRA_EXT_LEN: u32>(
    version: [u8; 5],
    version_len: u32,
    serial_number: [u8; 22],
    serial_number_len: u32,
    signature: [u8; 12],
    signature_len: u32,
    issuer: [u8; 124],
    issuer_len: u32,
    validity: [u8; 32],
    validity_len: u32,
    subject: [u8; 124],
    subject_len: u32,
    subject_public_key_info: [u8; 91],
    subject_public_key_info_len: u32,
    extensions_header: [u8; 8],
    extensions_header_len: u32,
    std_extensions: [u8; MAX_STD_EXT_LEN],
    std_extensions_len: u32,
    extra_extension: [u8; MAX_EXTRA_EXT_LEN],
    extra_extension_len: u32,
) -> ([u8; MAX_TBS_LEN], u32) {
    let version_offset = 4;
    let serial_number_offset = version_offset + version_len;
    let signature_offset = serial_number_offset + serial_number_len;
    let issuer_offset = signature_offset + signature_len;
    let validity_offset = issuer_offset + issuer_len;
    let subject_offset = validity_offset + validity_len;
    let subject_public_key_info_offset = subject_offset + subject_len;
    let ext_header_offset = subject_public_key_info_offset + subject_public_key_info_len;
    let std_ext_offset = ext_header_offset + extensions_header_len;
    let extra_ext_offset = std_ext_offset + std_extensions_len;
    let tbs_len = extra_ext_offset + extra_extension_len;
    assert(tbs_len <= MAX_TBS_LEN, "tbsCertificate length exceeds MAX_TBS_LEN");

    let mut buf: [u8; MAX_TBS_LEN] = [0; MAX_TBS_LEN];

    let tbs_value_len = tbs_len - 4;
    // Assume tbsCertificate length fits in 2 bytes
    assert(tbs_value_len >= 256);
    assert(tbs_value_len <= 65535);
    let tbs_len_bytes: [u8; 2] = (tbs_value_len as Field).to_be_bytes();

    buf[0] = 0x30;
    buf[1] = 0x82;
    buf[2] = tbs_len_bytes[0];
    buf[3] = tbs_len_bytes[1];
    for i in 0..5 {
        buf[4 + i] = version[i];
    }
    for i in 9..MAX_TBS_LEN {
        let before_sig = i < signature_offset;
        let before_iss = i < issuer_offset;
        let before_val = i < validity_offset;
        let before_sub = i < subject_offset;
        let before_spki = i < subject_public_key_info_offset;
        let before_ext_header = i < ext_header_offset;
        let before_std_ext = i < std_ext_offset;
        let before_extra_ext = i < extra_ext_offset;
        let before_end = i < tbs_len;

        // serial number
        let in_sn = before_sig;
        let sn_index = if in_sn { i - serial_number_offset } else { 0 };
        let sn_byte = if in_sn { serial_number[sn_index] } else { 0 };

        // signature
        let in_sig = !before_sig & before_iss;
        let sig_index = if in_sig { i - signature_offset } else { 0 };
        let sig_byte = if in_sig { signature[sig_index] } else { 0 };

        // issuer
        let in_iss = !before_iss & before_val;
        let iss_index = if in_iss { i - issuer_offset } else { 0 };
        let iss_byte = if in_iss { issuer[iss_index] } else { 0 };

        // validity
        let in_val = !before_val & before_sub;
        let val_index = if in_val { i - validity_offset } else { 0 };
        let val_byte = if in_val { validity[val_index] } else { 0 };

        // subject
        let in_sub = !before_sub & before_spki;
        let sub_index = if in_sub { i - subject_offset } else { 0 };
        let sub_byte = if in_sub { subject[sub_index] } else { 0 };

        // subject_public_key_info
        let in_spki = !before_spki & before_ext_header;
        let spki_index = if in_spki {
            i - subject_public_key_info_offset
        } else {
            0
        };
        let spki_byte = if in_spki {
            subject_public_key_info[spki_index]
        } else {
            0
        };

        // extensions header
        let in_ext_header = !before_ext_header & before_std_ext;
        let ext_header_index = if in_ext_header {
            i - ext_header_offset
        } else {
            0
        };
        let ext_header_byte = if in_ext_header {
            extensions_header[ext_header_index]
        } else {
            0
        };

        // standard extensions
        let in_std_ext = !before_std_ext & before_extra_ext;
        let std_ext_index = if in_std_ext { i - std_ext_offset } else { 0 };
        let std_ext_byte = if in_std_ext {
            std_extensions[std_ext_index]
        } else {
            0
        };

        // extra extension
        let in_extra_ext = !before_extra_ext & before_end;
        let extra_ext_index = if in_extra_ext {
            i - extra_ext_offset
        } else {
            0
        };
        let extra_ext_byte = if in_extra_ext {
            extra_extension[extra_ext_index]
        } else {
            0
        };

        buf[i] = if before_end {
            sn_byte
                + sig_byte
                + iss_byte
                + val_byte
                + sub_byte
                + spki_byte
                + ext_header_byte
                + std_ext_byte
                + extra_ext_byte
        } else {
            0
        };
    }

    (buf, tbs_len)
}

pub struct Extension<let MAX_OID_LEN: u32, let MAX_EXT_VALUE_LEN: u32> {
    id: [u8; MAX_OID_LEN],
    id_len: u32,
    critical: bool,
    value: [u8; MAX_EXT_VALUE_LEN],
    value_len: u32,
}

impl<let MAX_OID_LEN: u32, let MAX_EXT_VALUE_LEN: u32> Extension<MAX_OID_LEN, MAX_EXT_VALUE_LEN> {
    pub fn new(
        id: [u8; MAX_OID_LEN],
        id_len: u32,
        critical: bool,
        value: [u8; MAX_EXT_VALUE_LEN],
        value_len: u32,
    ) -> Self {
        assert(id_len <= MAX_OID_LEN);
        assert(value_len <= MAX_EXT_VALUE_LEN);

        Extension { id, id_len, critical, value, value_len }
    }

    /// Convert the extension to bytes
    /// Returns a tuple of the byte representation and its length
    /// Maximum length of the byte representation is
    /// 4 (SEQUENCE tag and length) + 2 (OBJECT ID tag and length) + MAX_OID_LEN
    /// + 3 (CRITICAL tag and length) + 4 (OCTET STRING tag and length) + MAX_EXT_VALUE_LEN
    pub fn to_bytes(self) -> ([u8; 4 + 2 + MAX_OID_LEN + 3 + 4 + MAX_EXT_VALUE_LEN], u32) {
        assert(self.value_len <= 65535, "extension value length must be <= 65535");

        let critical_len = if self.critical { 3 } else { 0 };

        let (value_len_encoded, value_len_encoded_size) = encode_length(self.value_len);

        let body_len = 2 // 06 XX (OBJECT ID tag and length)
            + self.id_len // XX ... XX (OBJECT ID)
            + critical_len // 0 (false) or 3 (true)
            + 1 // 04 (OCTET STRING tag)
            + value_len_encoded_size // length of extension value
            + self.value_len; // extension value
        assert(body_len <= 65531, "extension length without sequence header must be <= 65531");

        let (body_len_encoded, body_len_encoded_size) = encode_length(body_len);
        let total_len = 1 // 30 (SEQUENCE)
            + body_len_encoded_size // length of SEQUENCE
            + body_len; // value of SEQUENCE

        let mut bytes = [0; 4 + 2 + MAX_OID_LEN + 3 + 4 + MAX_EXT_VALUE_LEN];
        let mut index: u32 = 0;

        // sequence
        bytes[index] = 0x30; // Tag for SEQUENCE
        index += 1;
        // Length of SEQUENCE
        for i in 0..3 {
            if (i < body_len_encoded_size) {
                bytes[index] = body_len_encoded[i];
                index += 1;
            }
        }

        // extnID
        bytes[index] = 0x06; // Tag for OID
        index += 1;
        bytes[index] = self.id_len as u8; // Length of OID
        index += 1;
        for i in 0..MAX_OID_LEN {
            if (i < self.id_len) {
                bytes[index] = self.id[i];
                index += 1;
            }
        }

        // critical (if true)
        if self.critical {
            bytes[index] = 0x01; // Tag for BOOLEAN
            bytes[index + 1] = 0x01; // Length of BOOLEAN
            bytes[index + 2] = 0xff; // TRUE
        }
        index += critical_len;

        // extnValue
        // Tag for OCTET STRING
        bytes[index] = 0x04;
        index += 1;
        // Length of OCTET STRING
        for i in 0..3 {
            if (i < value_len_encoded_size) {
                bytes[index] = value_len_encoded[i];
                index += 1;
            }
        }
        // value
        for i in 0..MAX_EXT_VALUE_LEN {
            if (i < self.value_len) {
                bytes[index] = self.value[i];
                index += 1;
            }
        }

        (bytes, total_len)
    }
}

#[test]
fn test_encode_length() {
    let (len_encoded, len_encoded_size) = encode_length(1);
    assert(len_encoded == [0x01, 0x00, 0x00]);
    assert(len_encoded_size == 1);

    let (len_encoded, len_encoded_size) = encode_length(127);
    assert(len_encoded == [0x7f, 0x00, 0x00]);
    assert(len_encoded_size == 1);

    let (len_encoded, len_encoded_size) = encode_length(128);
    assert(len_encoded == [0x81, 0x80, 0x00]);
    assert(len_encoded_size == 2);

    let (len_encoded, len_encoded_size) = encode_length(255);
    assert(len_encoded == [0x81, 0xff, 0x00]);
    assert(len_encoded_size == 2);

    let (len_encoded, len_encoded_size) = encode_length(256);
    assert(len_encoded == [0x82, 0x01, 0x00]);
    assert(len_encoded_size == 3);

    let (len_encoded, len_encoded_size) = encode_length(65535);
    assert(len_encoded == [0x82, 0xff, 0xff]);
    assert(len_encoded_size == 3);
}

#[test]
fn test_key_usage_extension_to_bytes() {
    let ext = Extension::new(
        [0x55, 0x1d, 0x0f], // 2.5.29.15: key usage
        3,
        true,
        [0x03, 0x02, 0x02, 0x04], // keyCertSign
        4,
    );
    let (bytes, total_len) = ext.to_bytes();
    assert(
        bytes
            == [
                0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02,
                0x02, 0x04, 0, 0, 0, 0,
            ],
    );
    assert(total_len == 16);
}

#[test]
fn test_ski_extension_to_bytes() {
    let ext = Extension::new(
        [0x55, 0x1d, 0x0e], // 2.5.29.14: subject key identifier
        3,
        false,
        [
            0x04, 0x14, 0x99, 0xc7, 0x9c, 0xd7, 0x31, 0xc9, 0xe5, 0x40, 0xa4, 0x83, 0xf7, 0xde,
            0xd8, 0x5b, 0x1a, 0x45, 0xe5, 0x23, 0xad, 0x47,
        ], // subject key identifier with octet string header
        22,
    );
    let (bytes, total_len) = ext.to_bytes();
    assert(
        bytes
            == [
                0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x99, 0xc7, 0x9c,
                0xd7, 0x31, 0xc9, 0xe5, 0x40, 0xa4, 0x83, 0xf7, 0xde, 0xd8, 0x5b, 0x1a, 0x45, 0xe5,
                0x23, 0xad, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
    );
    assert(total_len == 31);
}
