use poseidon::poseidon::bn254::{hash_2, hash_8};

pub fn commit_attrs_hash_8(
    dn: [u8; 124],
    key_identifier: [u8; 20],
    pk_x: [u8; 32],
    pk_y: [u8; 32],
    r: Field,
) -> Field {
    let mut tbh = [0; 8];
    let mut slice = [0; 31];

    // dn[0], ..., dn[123]
    for i in 0..4 {
        for j in 0..31 {
            slice[j] = dn[i * 31 + j];
        }
        tbh[i] = Field::from_le_bytes(slice);
    }

    for j in 0..20 {
        slice[j] = key_identifier[j]; // kid[0], ..., kid[19]
    }
    for j in 20..31 {
        slice[j] = pk_x[j - 20]; // pk_x[0], ..., pk_x[10]
    }
    tbh[4] = Field::from_le_bytes(slice);

    for j in 0..21 {
        slice[j] = pk_x[11 + j]; // pk_x[11], ..., pk_x[31]
    }
    for j in 21..31 {
        slice[j] = pk_y[j - 21]; // pk_y[0], ..., pk_y[9]
    }
    tbh[5] = Field::from_le_bytes(slice);

    slice = [0; 31];
    for j in 0..22 {
        slice[j] = pk_y[10 + j]; // pk_y[10], ..., pk_y[31]
    }
    tbh[6] = Field::from_le_bytes(slice);

    tbh[7] = r;

    hash_8(tbh)
}

pub fn commit_attrs(
    dn: [u8; 124],
    key_identifier: [u8; 20],
    pk_x: [u8; 32],
    pk_y: [u8; 32],
    r: Field,
) -> Field {
    let mut state = 0;
    let mut slice = [0; 31];

    // dn[0], ..., dn[123]
    for j in 0..31 {
        slice[j] = dn[j];
    }
    state = Field::from_le_bytes(slice);

    for i in 1..4 {
        for j in 0..31 {
            slice[j] = dn[i * 31 + j];
        }
        state = hash_2([state, Field::from_le_bytes(slice)]);
    }

    for j in 0..20 {
        slice[j] = key_identifier[j]; // kid[0], ..., kid[19]
    }
    for j in 20..31 {
        slice[j] = pk_x[j - 20]; // pk_x[0], ..., pk_x[10]
    }
    state = hash_2([state, Field::from_le_bytes(slice)]);

    for j in 0..21 {
        slice[j] = pk_x[11 + j]; // pk_x[11], ..., pk_x[31]
    }
    for j in 21..31 {
        slice[j] = pk_y[j - 21]; // pk_y[0], ..., pk_y[9]
    }
    state = hash_2([state, Field::from_le_bytes(slice)]);

    slice = [0; 31];
    for j in 0..22 {
        slice[j] = pk_y[10 + j]; // pk_y[10], ..., pk_y[31]
    }
    state = hash_2([state, Field::from_le_bytes(slice)]);

    state = hash_2([state, r]);

    state
}
