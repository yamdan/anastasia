use std::convert::AsPrimitive;

global ADD: str<3> = "add";
global DEL: str<3> = "del";

pub comptime fn concat_chunks<let N: u32>(
    min_len: [u32; N - 1],
    max_len: [u32; N - 1],
    out_len: u32,
) -> Quoted {
    let mut add_positions = [0; N];
    add_positions[0] = 0;
    for i in 0..N - 1 {
        add_positions[i + 1] = add_positions[i] + min_len[i];
    }
    let mut del_positions = [0; N - 1];
    del_positions[0] = max_len[0];
    for i in 0..N - 2 {
        del_positions[i + 1] = del_positions[i] + max_len[i + 1];
    }

    for i in 0..N - 1 {
        assert(min_len[i] <= max_len[i], f"min_len[{i}] must be <= max_len[{i}]");
    }
    assert(del_positions[N - 2] <= out_len, "sum of max_len must be <= out_len");

    let add_arr = add_positions.mapi(|i, pos| (pos, (ADD, i)));
    let del_arr = del_positions.mapi(|i, pos| (pos, (DEL, i)));
    let arr = add_arr.concat(del_arr);
    let sorted_arr = arr.sort_via(|a, b| a.0 < b.0);

    let mut sequences = Vec::new();
    let mut operations = Vec::from_slice(&[0]);
    let mut from_index = 0;
    for inst in sorted_arr {
        let to_index = inst.0;
        let action = inst.1;
        if to_index == 0 {
            // Skip the initial add of chunk 0
            continue;
        }

        let range = (from_index, to_index);
        sequences.push((range, operations));

        if action.0 == ADD {
            operations.push(action.1);
        } else {
            let _ = operations.remove(0);
        }
        from_index = to_index;
    }
    let range = (from_index, out_len);
    sequences.push((range, operations));

    let header_buf = quote {
        let mut buf = [0; $out_len];
        let mut head = [0; $N];
        let mut chunk_byte = [0; $N];

        for i in 0..$N - 1 {
            assert(len[i] >= $min_len[i]);
            assert(len[i] <= $max_len[i]);
        }
        
        head[0] = 0;
        assert(head[0] >= $add_positions[0]);
        assert(head[0] < $del_positions[0]);
        for i in 0..$N - 2 {
            head[i + 1] = head[i] + len[i];
            assert(head[i + 1] >= $add_positions[i + 1]);
            assert(head[i + 1] < $del_positions[i + 1]);
        }
        head[$N - 1] = head[$N - 2] + len[$N - 2];
        assert(head[$N - 1] >= $add_positions[$N - 1]);
    };

    let mut inner_buf = quote{};

    // for (range, operations) in sequences
    while sequences.len() != 0 {
        let sequence = sequences.remove(0);
        let range = sequence.0;
        let mut operations = sequence.1;

        let mut cond_part = quote {
            let mut in_chunk: [bool; $N] = [false; $N];
            let mut acc_in_chunk = true;
        };
        let mut byte_part = quote {};

        // for op in operations
        while operations.len() != 0 {
            let op = operations.remove(0);

            cond_part = if operations.len() == 0 {
                quote {
                    $cond_part
                    in_chunk[$op] = acc_in_chunk;
                }
            } else {
                quote {
                    $cond_part
                    in_chunk[$op] = acc_in_chunk & i < head[$op + 1];
                    acc_in_chunk &= !in_chunk[$op];
                }
            };

            let op32: u32 = op.as_();
            let chunks = f"chunk_{op32}".quoted_contents();
            byte_part = quote {
                $byte_part

                chunk_byte[$op] = if in_chunk[$op] {
                    $chunks[i - head[$op]]
                } else {
                    0
                };

                buf[i] += chunk_byte[$op];
            };
        }

        inner_buf = quote {
            $inner_buf

            for i in $range.0..$range.1 {
                $cond_part

                $byte_part
            }
        };
    }

    let mut params = quote {};
    for i in 0..N - 1 {
        let chunk_i = f"chunk_{i}".quoted_contents();
        let max_len_i = max_len[i];
        params = quote {
            $params
            $chunk_i: [u8; $max_len_i],
        };
    }
    let len_params: u32 = (N - 1).as_();
    let chunk_i = f"chunk_{len_params}".quoted_contents();
    let last_add_position = add_positions[N - 1];
    params = quote {
        $params
        $chunk_i: [u8; $out_len - $last_add_position],
        len: [u32; $N - 1],
    };

    let quote_buf = quote {
        |
            $params          
        |
        {
            $header_buf
            $inner_buf
            buf
        }
    };

    quote_buf
}

#[test]
fn test_concat_chunks_2() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // (MAX_LEN_1: u32 = 6)
    let chunk_0 = [1, 1, 1, 1, 0];
    let len_0 = 4;
    let chunk_1 = [2, 2, 2, 2, 2, 0, 0, 0, 0];

    let result = concat_chunks!([2u32], [5u32], 11u32)(chunk_0, chunk_1, [len_0]);
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

    let result = concat_chunks!([2u32], [5u32], 11u32)(chunk_0, chunk_1, [len_0]);
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

    let _result = concat_chunks!([2u32], [5u32], 11u32)(chunk_0, chunk_1, [len_0]);
}

#[test]
fn test_concat_chunks_2_max_boundary() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // (MAX_LEN_1: u32 = 6)
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 5;
    let chunk_1 = [2, 2, 2, 2, 2, 2, 0, 0, 0];

    let result = concat_chunks!([2u32], [5u32], 11u32)(chunk_0, chunk_1, [len_0]);
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

    let _result = concat_chunks!([2u32], [5u32], 11u32)(chunk_0, chunk_1, [len_0]);
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
    let result = concat_chunks!([2u32, 4u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
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
    let result = concat_chunks!([2u32, 4u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
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
    let _result = concat_chunks!([2u32, 4u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
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
    let _result = concat_chunks!([2u32, 4u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
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
    let result = concat_chunks!([2u32, 4u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
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
    let _result = concat_chunks!([2u32, 4u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
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
    let _result = concat_chunks!([2u32, 4u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
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
    let result = concat_chunks!([2u32, 2u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
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
    let result = concat_chunks!([2u32, 2u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
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
    let _result = concat_chunks!([2u32, 2u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
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
    let _result = concat_chunks!([2u32, 2u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
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
    let result = concat_chunks!([2u32, 2u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
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
    let _result = concat_chunks!([2u32, 2u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
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
    let _result = concat_chunks!([2u32, 2u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
}

#[test]
fn test_concat_chunks_4() {
    // MIN_LEN_0: u32 = 2;
    // MAX_LEN_0: u32 = 5;
    // MIN_LEN_1: u32 = 4;
    // MAX_LEN_1: u32 = 6;
    // MIN_LEN_2: u32 = 2;
    // MAX_LEN_2: u32 = 3;
    // (MAX_LEN_3: u32 = 5)
    // TOTAL_MAX_LEN: u32 = 16;
    let chunk_0 = [1, 1, 1, 1, 0];
    let len_0 = 4;
    let chunk_1 = [2, 2, 2, 2, 2, 0];
    let len_1 = 5;
    let chunk_2 = [3, 3, 0];
    let len_2 = 2;
    let chunk_3 = [4, 4, 4, 4, 0, 0, 0, 0];
    let result = concat_chunks!([2u32, 4u32, 2u32], [5u32, 6u32, 3u32], 16u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        chunk_3,
        [len_0, len_1, len_2],
    );
    let expected = [1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 4, 4, 4, 4, 0];
    assert_eq(result, expected);
}
