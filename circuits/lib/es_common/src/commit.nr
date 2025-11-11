use std::hash::pedersen_commitment;

pub fn commit_attrs(
    dn: [u8; 124],
    key_identifier: [u8; 20],
    pk_x: [u8; 48],
    pk_y: [u8; 48],
    r: Field,
) -> (Field, Field) {
    let mut tbh = [0; 10];
    let mut slice = [0; 31];

    // dn[0], ..., dn[123]
    for i in 0..4 {
        for j in 0..31 {
            slice[j] = dn[i * 31 + j];
        }
        tbh[i] = Field::from_le_bytes(slice);
    }

    // key_id[0..20]
    for j in 0..20 {
        slice[j] = key_identifier[j];
    }
    for j in 20..31 {
        slice[j] = 0;
    }
    tbh[4] = Field::from_le_bytes(slice);

    // pk_x[0..31]
    for j in 0..31 {
        slice[j] = pk_x[j];
    }
    tbh[5] = Field::from_le_bytes(slice);

    // pk_x[31..48] + padding
    for j in 0..17 {
        slice[j] = pk_x[31 + j];
    }
    for j in 17..31 {
        slice[j] = 0;
    }
    tbh[6] = Field::from_le_bytes(slice);

    // pk_y[0..31]
    for j in 0..31 {
        slice[j] = pk_y[j];
    }
    tbh[7] = Field::from_le_bytes(slice);

    // pk_y[31..48] + padding
    for j in 0..17 {
        slice[j] = pk_y[31 + j];
    }
    for j in 17..31 {
        slice[j] = 0;
    }
    tbh[8] = Field::from_le_bytes(slice);

    // r
    tbh[9] = r;

    let cmt = pedersen_commitment(tbh);

    // Commitment must not be the point at infinity
    assert(!cmt.is_infinite, "Pedersen commitment must not be infinite");

    (cmt.x, cmt.y)
}

pub fn check_commitments(
    dn: [u8; 124],
    key_identifier: [u8; 20],
    pk_x: [u8; 48],
    pk_y: [u8; 48],
    cmt: (Field, Field),
    cmt_r: Field,
) {
    let cmt_generated = commit_attrs(dn, key_identifier, pk_x, pk_y, cmt_r);
    assert(cmt_generated == cmt, "Commitment does not match");
}
