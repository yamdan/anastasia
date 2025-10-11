fn u8_to_two_ascii_bytes(mut n: u8) -> [u8; 2] {
    assert(n < 100);
    let mut buf: [u8; 2] = [0; 2];
    buf[0] = ((n / 10) as u8) + 48;
    buf[1] = ((n % 10) as u8) + 48;
    buf
}

// Encode a length value according to ASN.1 DER rules
// Note: This function assumes that the length is <= 65535
pub fn encode_length(length: u32) -> ([u8; 3], u32) {
    assert(length <= 65535, "Length must be <= 65535");

    let mut len_encoded = [0; 3];
    let mut len_encoded_size = 0;
    if (length <= 127) {
        len_encoded = [length as u8, 0, 0];
        len_encoded_size = 1;
    } else if (length <= 255) {
        len_encoded = [0x81, length as u8, 0];
        len_encoded_size = 2;
    } else {
        len_encoded = [0x82, (length >> 8) as u8, length as u8];
        len_encoded_size = 3;
    }
    (len_encoded, len_encoded_size)
}

pub struct UtcTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

impl UtcTime {
    pub fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Self {
        assert(1950 <= year);
        assert(year <= 2050);
        assert(month >= 1);
        assert(month <= 12);
        assert(day >= 1);
        assert(day <= 31); // Simplified check, does not account for different month lengths or leap years
        assert(hour < 24);
        assert(minute < 60);
        assert(second < 60);

        UtcTime { year, month, day, hour, minute, second }
    }

    pub fn from_bytes(bytes: [u8; 7]) -> Self {
        let year = ((bytes[0] as u16) << 8) | (bytes[1] as u16);
        let month = bytes[2];
        let day = bytes[3];
        let hour = bytes[4];
        let minute = bytes[5];
        let second = bytes[6];

        UtcTime::new(year, month, day, hour, minute, second)
    }

    pub fn to_bytes(self) -> [u8; 15] {
        let mut bytes: [u8; 15] = [0; 15];

        bytes[0] = 0x17; // Tag for UTCTime
        bytes[1] = 0x0d; // Length of the UTCTime string (fixed 13 bytes)

        let year = if self.year < 2000 {
            (self.year - 1900) as u8
        } else {
            (self.year - 2000) as u8
        };
        let year_bytes = u8_to_two_ascii_bytes(year);
        bytes[2] = year_bytes[0];
        bytes[3] = year_bytes[1];

        let month_bytes = u8_to_two_ascii_bytes(self.month);
        bytes[4] = month_bytes[0];
        bytes[5] = month_bytes[1];

        let day_bytes = u8_to_two_ascii_bytes(self.day);
        bytes[6] = day_bytes[0];
        bytes[7] = day_bytes[1];

        let hour_bytes = u8_to_two_ascii_bytes(self.hour);
        bytes[8] = hour_bytes[0];
        bytes[9] = hour_bytes[1];

        let minute_bytes = u8_to_two_ascii_bytes(self.minute);
        bytes[10] = minute_bytes[0];
        bytes[11] = minute_bytes[1];

        let second_bytes = u8_to_two_ascii_bytes(self.second);
        bytes[12] = second_bytes[0];
        bytes[13] = second_bytes[1];

        bytes[14] = 0x5a; // Z

        bytes
    }

    pub fn isBefore(self, new: UtcTime) -> bool {
        if self.year < new.year {
            true
        } else if self.year > new.year {
            false
        } else if self.month < new.month {
            true
        } else if self.month > new.month {
            false
        } else if self.day < new.day {
            true
        } else if self.day > new.day {
            false
        } else if self.hour < new.hour {
            true
        } else if self.hour > new.hour {
            false
        } else if self.minute < new.minute {
            true
        } else if self.minute > new.minute {
            false
        } else {
            self.second < new.second
        }
    }
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
