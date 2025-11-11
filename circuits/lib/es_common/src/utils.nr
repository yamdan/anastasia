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
