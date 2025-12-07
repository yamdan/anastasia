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

pub fn encode_length_1(length: u32) -> u8 {
    assert(length <= 127, "Length must be <= 127");
    length as u8
}

pub fn encode_length_2(length: u32) -> [u8; 2] {
    assert(length <= 255, "Length must be <= 255");
    [0x81, length as u8]
}

pub fn encode_length_3(length: u32) -> [u8; 3] {
    assert(length <= 65535, "Length must be <= 65535");
    [0x82, (length >> 8) as u8, length as u8]
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

pub fn to_bignum_limbs<let N: u32>(bytes: [u8; N]) -> [u128; (N - 1) / 15 + 1] {
    let mut limbs: [u128; (N - 1) / 15 + 1] = [0; (N - 1) / 15 + 1];
    let r = if N % 15 == 0 { 15 } else { N % 15 };
    for i in 0..r {
        limbs[limbs.len() - 1] += (bytes[i] as u128) << ((r - i - 1) * 8) as u8;
    }
    for n in 1..limbs.len() {
        for i in 0..15 {
            limbs[limbs.len() - 1 - n] +=
                (bytes[r + (n - 1) * 15 + i] as u128) << ((14 - i) * 8) as u8;
        }
    }
    limbs
}

pub fn concat_chunks_2<let MIN_LEN_0: u32, let MAX_LEN_0: u32, let OUT_LEN: u32>(
    chunk_0_bytes: [u8; MAX_LEN_0],
    len_0: u32,
    chunk_1_bytes: [u8; OUT_LEN - MIN_LEN_0],
) -> [u8; OUT_LEN] {
    let MIN_BOUNDARY_0: u32 = MIN_LEN_0;
    let MAX_BOUNDARY_0: u32 = MAX_LEN_0;

    println(f"chunk_0:    0 -- {len_0}");
    println(f"BOUNDARY_0: {MIN_BOUNDARY_0} -- {MAX_BOUNDARY_0}");
    println(f"chunk_1:    {len_0} -- {OUT_LEN}");
    println("");

    assert(len_0 >= MIN_BOUNDARY_0);
    assert(len_0 <= MAX_BOUNDARY_0);

    let mut buf: [u8; OUT_LEN] = [0; OUT_LEN];

    // Copy chunk 0
    for i in 0..MIN_BOUNDARY_0 {
        let chunk_0_byte = chunk_0_bytes[i];

        buf[i] = chunk_0_byte;
    }

    // Copy chunk 0 and chunk 1
    for i in MIN_BOUNDARY_0..MAX_BOUNDARY_0 {
        let in_chunk_0 = i < len_0;

        let chunk_0_byte = if in_chunk_0 { chunk_0_bytes[i] } else { 0 };

        let chunk_1_byte = if !in_chunk_0 {
            chunk_1_bytes[i - len_0]
        } else {
            0
        };

        buf[i] = chunk_0_byte + chunk_1_byte;
    }

    // Copy chunk 1
    for i in MAX_BOUNDARY_0..OUT_LEN {
        let chunk_1_byte = chunk_1_bytes[i - len_0];

        buf[i] = chunk_1_byte;
    }

    buf
}

// pub comptime fn build_concat_chunks_3(in_1: u32, in_2: u32, out_0: u32, out_1: u32) -> Quoted {
//     let in_0_block = quote {
//         let chunk_0_byte = chunk_0_bytes[i];
//     };

//     let in_1_block = quote {
//         let in_chunk_0 = i < acc_len_0;
//         let chunk_1_byte = if !in_chunk_0 {
//             chunk_1_bytes[i - acc_len_0]
//         } else {
//             0
//        };
//     };

//     let in_2_block = quote {
//         let in_chunk_1 = i < acc_len_1;
//         let chunk_2_byte = if !in_chunk_1 {
//             chunk_2_bytes[i - acc_len_1]
//         } else {
//             0
//         };
//     };

//     let arr = [(in_1, in_1_block), (1, in_2), (2, out_0), (3, out_1)];
//     let sorted_arr = arr.sort_via(|a, b| a.1 < b.1);

//     for x in sorted_arr {
//         let x0 = x.0;
//         let x1 = x.1;
//         println(f"Index: {x0}, Value: {x1}");

//         let block = if x.0 == 0 {
//             quote {
//                 let chunk_1_byte = if !in_chunk_0 {
//                     chunk_1_bytes[i - acc_len_0]
//                 } else {
//                     0
//                };
//             }
//         } else if x.0 == 1 {
//             quote {
//                 let chunk_2_byte = if !in_chunk_1 {
//                     chunk_2_bytes[i - acc_len_1]
//                 } else {
//                     0
//                 };
//             }
//         } else if x.0 == 2 {
//             quote {
//                 let chunk_0_byte = if in_chunk_0 { chunk_0_bytes[i] } else { 0 };
//             }
//         } else {
//             quote {
//                 let chunk_1_byte = if in_chunk_1 {
//                     chunk_1_bytes[i - acc_len_0]
//                 } else {
//                     0
//                 };
//             }
//         };
//         println(f"Generated block for index {x0}:\n{block}");
//     }
//     quote {}
// }

pub fn concat_chunks_3<let MIN_LEN_0: u32, let MAX_LEN_0: u32, let MIN_LEN_1: u32, let MAX_LEN_1: u32, let OUT_LEN: u32>(
    chunk_0_bytes: [u8; MAX_LEN_0],
    len_0: u32,
    chunk_1_bytes: [u8; MAX_LEN_1],
    len_1: u32,
    chunk_2_bytes: [u8; OUT_LEN - MIN_LEN_0 - MIN_LEN_1],
) -> [u8; OUT_LEN] {
    let ADD_1: u32 = MIN_LEN_0;
    let ADD_2: u32 = ADD_1 + MIN_LEN_1;
    let DEL_0: u32 = MAX_LEN_0;
    let DEL_1: u32 = DEL_0 + MAX_LEN_1;

    assert(MIN_LEN_0 <= MAX_LEN_0, "MIN_LEN_0 must be <= MAX_LEN_0");
    assert(MIN_LEN_1 <= MAX_LEN_1, "MIN_LEN_1 must be <= MAX_LEN_1");
    assert(DEL_0 <= ADD_2, "MAX_LEN_0 must be <= MIN_LEN_0 + MIN_LEN_1");
    assert(DEL_1 <= OUT_LEN, "MAX_LEN_0 + MAX_LEN_1 must be <= OUT_LEN");

    let acc_len_0 = len_0;
    let acc_len_1 = len_0 + len_1;

    println(f"chunk_0:    0 -- {acc_len_0}");
    println(f"BOUNDARY_0: {ADD_1} -- {DEL_0}");
    println(f"chunk_1:    {acc_len_0} -- {acc_len_1}");
    println(f"BOUNDARY_1: {ADD_2} -- {DEL_1}");
    println("");

    assert(acc_len_0 >= MIN_LEN_0);
    assert(acc_len_0 <= MAX_LEN_0);
    assert(acc_len_1 >= MIN_LEN_0 + MIN_LEN_1);
    assert(acc_len_1 <= MAX_LEN_0 + MAX_LEN_1);

    let mut buf: [u8; OUT_LEN] = [0; OUT_LEN];

    // Copy chunk 0
    for i in 0..ADD_1 {
        let mut acc_in_chunk = true;
        let in_chunk_0 = acc_in_chunk;

        let chunk_0_byte = if in_chunk_0 { chunk_0_bytes[i] } else { 0 };

        buf[i] += chunk_0_byte;
    }

    // Copy chunk 0 and chunk 1
    for i in ADD_1..DEL_0 {
        let mut acc_in_chunk = true;
        let in_chunk_0 = acc_in_chunk & i < acc_len_0;
        acc_in_chunk &= !in_chunk_0;
        let in_chunk_1 = acc_in_chunk;

        let chunk_0_byte = if in_chunk_0 { chunk_0_bytes[i] } else { 0 };

        let chunk_1_byte = if in_chunk_1 {
            chunk_1_bytes[i - acc_len_0]
        } else {
            0
        };

        buf[i] += chunk_0_byte;
        buf[i] += chunk_1_byte;
    }

    // Copy chunk 1
    for i in DEL_0..ADD_2 {
        let mut acc_in_chunk = true;
        let in_chunk_1 = acc_in_chunk;

        let chunk_1_byte = if in_chunk_1 {
            chunk_1_bytes[i - acc_len_0]
        } else {
            0
        };

        buf[i] += chunk_1_byte;
    }

    // Copy chunk 1 and chunk 2
    for i in ADD_2..DEL_1 {
        let mut acc_in_chunk = true;
        let in_chunk_1 = acc_in_chunk & i < acc_len_1;
        acc_in_chunk &= !in_chunk_1;
        let in_chunk_2 = acc_in_chunk;

        let chunk_1_byte = if in_chunk_1 {
            chunk_1_bytes[i - acc_len_0]
        } else {
            0
        };
        let chunk_2_byte = if in_chunk_2 {
            chunk_2_bytes[i - acc_len_1]
        } else {
            0
        };

        buf[i] += chunk_1_byte;
        buf[i] += chunk_2_byte;
    }

    // Copy chunk 2
    for i in DEL_1..OUT_LEN {
        let mut acc_in_chunk = true;
        let in_chunk_2 = acc_in_chunk;

        let chunk_2_byte = if in_chunk_2 {
            chunk_2_bytes[i - acc_len_1]
        } else {
            0
        };

        buf[i] += chunk_2_byte;
    }

    buf
}

pub fn concat_chunks_3_2<let MIN_LEN_0: u32, let MAX_LEN_0: u32, let MIN_LEN_1: u32, let MAX_LEN_1: u32, let OUT_LEN: u32>(
    chunk_0_bytes: [u8; MAX_LEN_0],
    len_0: u32,
    chunk_1_bytes: [u8; MAX_LEN_1],
    len_1: u32,
    chunk_2_bytes: [u8; OUT_LEN - MIN_LEN_0 - MIN_LEN_1],
) -> [u8; OUT_LEN] {
    let ADD_1: u32 = MIN_LEN_0;
    let ADD_2: u32 = ADD_1 + MIN_LEN_1;
    let DEL_0: u32 = MAX_LEN_0;
    let DEL_1: u32 = DEL_0 + MAX_LEN_1;

    assert(MIN_LEN_0 <= MAX_LEN_0, "MIN_LEN_0 must be <= MAX_LEN_0");
    assert(MIN_LEN_1 <= MAX_LEN_1, "MIN_LEN_1 must be <= MAX_LEN_1");
    assert(ADD_2 <= DEL_0, "MIN_LEN_0 + MIN_LEN_1 must be <= MAX_LEN_0");
    assert(DEL_1 <= OUT_LEN, "MAX_LEN_0 + MAX_LEN_1 must be <= OUT_LEN");

    let acc_len_0 = len_0;
    let acc_len_1 = len_0 + len_1;

    println(f"chunk_0:    0 -- {acc_len_0}");
    println(f"BOUNDARY_0: {ADD_1} -- {DEL_0}");
    println(f"chunk_1:    {acc_len_0} -- {acc_len_1}");
    println(f"BOUNDARY_1: {ADD_2} -- {DEL_1}");
    println("");

    assert(acc_len_0 >= MIN_LEN_0);
    assert(acc_len_0 <= MAX_LEN_0);
    assert(acc_len_1 >= MIN_LEN_0 + MIN_LEN_1);
    assert(acc_len_1 <= MAX_LEN_0 + MAX_LEN_1);

    let mut buf: [u8; OUT_LEN] = [0; OUT_LEN];

    // Copy chunk 0
    for i in 0..ADD_1 {
        let mut acc_in_chunk = true;
        let in_chunk_0 = acc_in_chunk;

        let chunk_0_byte = if in_chunk_0 { chunk_0_bytes[i] } else { 0 };

        buf[i] += chunk_0_byte;
    }

    // Copy chunk 0 and chunk 1
    for i in ADD_1..ADD_2 {
        let mut acc_in_chunk = true;
        let in_chunk_0 = acc_in_chunk & i < acc_len_0;
        acc_in_chunk &= !in_chunk_0;
        let in_chunk_1 = acc_in_chunk;

        let chunk_0_byte = if in_chunk_0 { chunk_0_bytes[i] } else { 0 };

        let chunk_1_byte = if in_chunk_1 {
            chunk_1_bytes[i - acc_len_0]
        } else {
            0
        };

        buf[i] += chunk_0_byte;
        buf[i] += chunk_1_byte;
    }

    // Copy chunk 0 and chunk 1 and chunk 2
    for i in ADD_2..DEL_0 {
        let mut acc_in_chunk = true;
        let in_chunk_0 = acc_in_chunk & i < acc_len_0;
        acc_in_chunk &= !in_chunk_0;
        let in_chunk_1 = acc_in_chunk & i < acc_len_1;
        acc_in_chunk &= !in_chunk_1;
        let in_chunk_2 = acc_in_chunk;

        let chunk_0_byte = if in_chunk_0 { chunk_0_bytes[i] } else { 0 };

        let chunk_1_byte = if in_chunk_1 {
            chunk_1_bytes[i - acc_len_0]
        } else {
            0
        };

        let chunk_2_byte = if in_chunk_2 {
            chunk_2_bytes[i - acc_len_1]
        } else {
            0
        };

        buf[i] += chunk_0_byte;
        buf[i] += chunk_1_byte;
        buf[i] += chunk_2_byte;
    }

    // Copy chunk 1 and chunk 2
    for i in DEL_0..DEL_1 {
        let mut acc_in_chunk = true;
        let in_chunk_1 = acc_in_chunk & i < acc_len_1;
        acc_in_chunk &= !in_chunk_1;
        let in_chunk_2 = acc_in_chunk;

        let chunk_1_byte = if in_chunk_1 {
            chunk_1_bytes[i - acc_len_0]
        } else {
            0
        };

        let chunk_2_byte = if in_chunk_2 {
            chunk_2_bytes[i - acc_len_1]
        } else {
            0
        };

        buf[i] += chunk_1_byte;
        buf[i] += chunk_2_byte;
    }

    // Copy chunk 2
    for i in DEL_1..OUT_LEN {
        let mut acc_in_chunk = true;
        let in_chunk_2 = acc_in_chunk;

        let chunk_2_byte = if in_chunk_2 {
            chunk_2_bytes[i - acc_len_1]
        } else {
            0
        };

        buf[i] += chunk_2_byte;
    }

    buf
}

#[test]
fn test_to_bignum_limbs() {
    let bytes: [u8; 1] = [0x01];
    let limbs = to_bignum_limbs(bytes);
    assert_eq(limbs.len(), 1);
    assert_eq(limbs[0], 0x01);

    let bytes: [u8; 24] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    ];
    let limbs = to_bignum_limbs(bytes);
    assert_eq(limbs.len(), 2);
    assert_eq(limbs[0], 0x0a0b0c0d0e0f101112131415161718);
    assert_eq(limbs[1], 0x010203040506070809);

    let bytes: [u8; 30] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let limbs = to_bignum_limbs(bytes);
    assert_eq(limbs.len(), 2);
    assert_eq(limbs[0], 0x1112131415161718191a1b1c1d1e1f);
    assert_eq(limbs[1], 0x0102030405060708090a0b0c0d0e0f);

    let bytes: [u8; 48] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x31, 0x32, 0x33,
    ];
    let limbs = to_bignum_limbs(bytes);
    assert_eq(limbs.len(), 4);
    assert_eq(limbs[0], 0x2425262728292a2b2c2d2e2f313233);
    assert_eq(limbs[1], 0x1415161718191a1b1c1d1e1f212223);
    assert_eq(limbs[2], 0x0405060708090a0b0c0d0e0f111213);
    assert_eq(limbs[3], 0x010203);
}

#[test]
fn test_concat_chunks_2() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // (MAX_LEN_1: u32 = 6)
    let chunk_0 = [1, 1, 1, 1, 0];
    let len_0 = 4;
    let chunk_1 = [2, 2, 2, 2, 2, 0, 0, 0, 0];

    let result = concat_chunks_2::<2, 5, 11>(chunk_0, len_0, chunk_1);
    let expected = [1, 1, 1, 1, 2, 2, 2, 2, 2, 0, 0];
    assert_eq(result, expected);
}

#[test]
fn test_concat_chunks_2_min_boundary() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // (MAX_LEN_1: u32 = 6)
    let chunk_0 = [1, 1, 0, 0, 0];
    let len_0 = 2;
    let chunk_1 = [2, 2, 2, 2, 2, 0, 0, 0, 0];

    let result = concat_chunks_2::<2, 5, 11>(chunk_0, len_0, chunk_1);
    let expected = [1, 1, 2, 2, 2, 2, 2, 0, 0, 0, 0];
    assert_eq(result, expected);
}

#[test(should_fail_with = "Failed constraint")]
fn test_concat_chunks_2_beyond_min_boundary() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // (MAX_LEN_1: u32 = 6)
    let chunk_0 = [1, 0, 0, 0, 0];
    let len_0 = 1;
    let chunk_1 = [2, 2, 2, 2, 2, 0, 0, 0, 0];

    let _result = concat_chunks_2::<2, 5, 11>(chunk_0, len_0, chunk_1);
}

#[test]
fn test_concat_chunks_2_max_boundary() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // (MAX_LEN_1: u32 = 6)
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 5;
    let chunk_1 = [2, 2, 2, 2, 2, 2, 0, 0, 0];

    let result = concat_chunks_2::<2, 5, 11>(chunk_0, len_0, chunk_1);
    let expected = [1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2];
    assert_eq(result, expected);
}

#[test(should_fail_with = "Failed constraint")]
fn test_concat_chunks_2_beyond_max_boundary() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // (MAX_LEN_1: u32 = 6)
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 6;
    let chunk_1 = [2, 2, 2, 2, 2, 2, 0, 0, 0];

    let _result = concat_chunks_2::<2, 5, 11>(chunk_0, len_0, chunk_1);
}

#[test]
fn test_concat_chunks_3() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // MIN_LEN_1: u32 = 4;
    // MAX_LEN_1: u32 = 6;
    // (MAX_LEN_2: u32 = 3)
    let chunk_0 = [1, 1, 1, 1, 0];
    let len_0 = 4;
    let chunk_1 = [2, 2, 2, 2, 2, 0];
    let len_1 = 5;
    let chunk_2 = [3, 3, 0, 0, 0, 0, 0, 0];
    let result = concat_chunks_3::<2, 5, 4, 6, 14>(chunk_0, len_0, chunk_1, len_1, chunk_2);
    let expected = [1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 0, 0, 0];
    assert_eq(result, expected);
}

#[test]
fn test_concat_chunks_3_min_boundary() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // MIN_LEN_1: u32 = 4;
    // MAX_LEN_1: u32 = 6;
    // (MAX_LEN_2: u32 = 3)
    let chunk_0 = [1, 1, 0, 0, 0];
    let len_0 = 2;
    let chunk_1 = [2, 2, 2, 2, 0, 0];
    let len_1 = 4;
    let chunk_2 = [3, 3, 0, 0, 0, 0, 0, 0];
    let result = concat_chunks_3::<2, 5, 4, 6, 14>(chunk_0, len_0, chunk_1, len_1, chunk_2);
    let expected = [1, 1, 2, 2, 2, 2, 3, 3, 0, 0, 0, 0, 0, 0];
    assert_eq(result, expected);
}

#[test(should_fail_with = "Failed constraint")]
fn test_concat_chunks_3_beyond_min_boundary_0() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // MIN_LEN_1: u32 = 4;
    // MAX_LEN_1: u32 = 6;
    // (MAX_LEN_2: u32 = 3)
    let chunk_0 = [1, 0, 0, 0, 0];
    let len_0 = 1;
    let chunk_1 = [2, 2, 2, 2, 0, 0];
    let len_1 = 4;
    let chunk_2 = [3, 3, 0, 0, 0, 0, 0, 0];
    let _result = concat_chunks_3::<2, 5, 4, 6, 14>(chunk_0, len_0, chunk_1, len_1, chunk_2);
}

#[test(should_fail_with = "Failed constraint")]
fn test_concat_chunks_3_beyond_min_boundary_1() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // MIN_LEN_1: u32 = 4;
    // MAX_LEN_1: u32 = 6;
    // (MAX_LEN_2: u32 = 3)
    let chunk_0 = [1, 1, 0, 0, 0];
    let len_0 = 2;
    let chunk_1 = [2, 2, 2, 0, 0, 0];
    let len_1 = 3;
    let chunk_2 = [3, 3, 0, 0, 0, 0, 0, 0];
    let _result = concat_chunks_3::<2, 5, 4, 6, 14>(chunk_0, len_0, chunk_1, len_1, chunk_2);
}

#[test]
fn test_concat_chunks_3_max_boundary() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // MIN_LEN_1: u32 = 4;
    // MAX_LEN_1: u32 = 6;
    // (MAX_LEN_2: u32 = 3)
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 5;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 6;
    let chunk_2 = [3, 3, 3, 0, 0, 0, 0, 0];
    let result = concat_chunks_3::<2, 5, 4, 6, 14>(chunk_0, len_0, chunk_1, len_1, chunk_2);
    let expected = [1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3];
    assert_eq(result, expected);
}

#[test(should_fail_with = "Failed constraint")]
fn test_concat_chunks_3_beyond_max_boundary_0() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // MIN_LEN_1: u32 = 4;
    // MAX_LEN_1: u32 = 6;
    // (MAX_LEN_2: u32 = 3)
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 6;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 6;
    let chunk_2 = [3, 3, 3, 0, 0, 0, 0, 0];
    let _result = concat_chunks_3::<2, 5, 4, 6, 14>(chunk_0, len_0, chunk_1, len_1, chunk_2);
}

#[test(should_fail_with = "Failed constraint")]
fn test_concat_chunks_3_beyond_max_boundary_1() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // MIN_LEN_1: u32 = 4;
    // MAX_LEN_1: u32 = 6;
    // (MAX_LEN_2: u32 = 3)
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 5;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 7;
    let chunk_2 = [3, 3, 3, 0, 0, 0, 0, 0];
    let _result = concat_chunks_3::<2, 5, 4, 6, 14>(chunk_0, len_0, chunk_1, len_1, chunk_2);
}

#[test]
fn test_concat_chunks_3_2() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // MIN_LEN_1: u32 = 2;
    // MAX_LEN_1: u32 = 6;
    // (MAX_LEN_2: u32 = 3)
    let chunk_0 = [1, 1, 1, 1, 0];
    let len_0 = 4;
    let chunk_1 = [2, 2, 2, 2, 2, 0];
    let len_1 = 5;
    let chunk_2 = [3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
    let result = concat_chunks_3_2::<2, 5, 2, 6, 14>(chunk_0, len_0, chunk_1, len_1, chunk_2);
    let expected = [1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 0, 0, 0];
    assert_eq(result, expected);
}

#[test]
fn test_concat_chunks_3_2_min_boundary() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // MIN_LEN_1: u32 = 2;
    // MAX_LEN_1: u32 = 6;
    // (MAX_LEN_2: u32 = 3)
    let chunk_0 = [1, 1, 0, 0, 0];
    let len_0 = 2;
    let chunk_1 = [2, 2, 0, 0, 0, 0];
    let len_1 = 2;
    let chunk_2 = [3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
    let result = concat_chunks_3_2::<2, 5, 2, 6, 14>(chunk_0, len_0, chunk_1, len_1, chunk_2);
    let expected = [1, 1, 2, 2, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq(result, expected);
}

#[test(should_fail_with = "Failed constraint")]
fn test_concat_chunks_3_2_beyond_min_boundary_0() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // MIN_LEN_1: u32 = 2;
    // MAX_LEN_1: u32 = 6;
    // (MAX_LEN_2: u32 = 3)
    let chunk_0 = [1, 0, 0, 0, 0];
    let len_0 = 1;
    let chunk_1 = [2, 2, 2, 2, 0, 0];
    let len_1 = 4;
    let chunk_2 = [3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
    let _result = concat_chunks_3_2::<2, 5, 2, 6, 14>(chunk_0, len_0, chunk_1, len_1, chunk_2);
}

#[test(should_fail_with = "Failed constraint")]
fn test_concat_chunks_3_2_beyond_min_boundary_1() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // MIN_LEN_1: u32 = 2;
    // MAX_LEN_1: u32 = 6;
    // (MAX_LEN_2: u32 = 3)
    let chunk_0 = [1, 1, 0, 0, 0];
    let len_0 = 2;
    let chunk_1 = [2, 0, 0, 0, 0, 0];
    let len_1 = 1;
    let chunk_2 = [3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
    let _result = concat_chunks_3_2::<2, 5, 2, 6, 14>(chunk_0, len_0, chunk_1, len_1, chunk_2);
}

#[test]
fn test_concat_chunks_3_2_max_boundary() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // MIN_LEN_1: u32 = 2;
    // MAX_LEN_1: u32 = 6;
    // (MAX_LEN_2: u32 = 3)
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 5;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 6;
    let chunk_2 = [3, 3, 3, 0, 0, 0, 0, 0, 0, 0];
    let result = concat_chunks_3_2::<2, 5, 2, 6, 14>(chunk_0, len_0, chunk_1, len_1, chunk_2);
    let expected = [1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3];
    assert_eq(result, expected);
}

#[test(should_fail_with = "Failed constraint")]
fn test_concat_chunks_3_2_beyond_max_boundary_0() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // MIN_LEN_1: u32 = 2;
    // MAX_LEN_1: u32 = 6;
    // (MAX_LEN_2: u32 = 3)
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 6;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 6;
    let chunk_2 = [3, 3, 3, 0, 0, 0, 0, 0, 0, 0];
    let _result = concat_chunks_3_2::<2, 5, 2, 6, 14>(chunk_0, len_0, chunk_1, len_1, chunk_2);
}

#[test(should_fail_with = "Failed constraint")]
fn test_concat_chunks_3_2_beyond_max_boundary_1() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // MIN_LEN_1: u32 = 2;
    // MAX_LEN_1: u32 = 6;
    // (MAX_LEN_2: u32 = 3)
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 5;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 7;
    let chunk_2 = [3, 3, 3, 0, 0, 0, 0, 0, 0, 0];
    let _result = concat_chunks_3_2::<2, 5, 2, 6, 14>(chunk_0, len_0, chunk_1, len_1, chunk_2);
}

