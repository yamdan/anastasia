use std::convert::AsPrimitive;

pub comptime fn concat_chunks<let N: u32>(ranges: [(u32, u32); N]) -> Quoted {
    let min_len = ranges.map(|r| r.0);
    let max_len = ranges.map(|r| r.1);
    let out_len = max_len.reduce(|a, b| a + b);

    // Parameters part
    let mut params = quote {};
    for i in 0..N {
        let chunk_i = f"chunk_{i}".quoted_contents();
        let max_len_i = max_len[i];
        params = quote {
            $params
            $chunk_i: [u8; $max_len_i],
        };
    }
    params = quote {
        $params
        lengths: [u32; $N],
    };

    // Function body part
    let mut func_body = quote {
        let mut buf = [0; $out_len];
        let mut offset: u32 = 0;
    };
    for i in 0..N {
        let chunk_i = f"chunk_{i}".quoted_contents();
        let min_len_i = min_len[i];
        let max_len_i = max_len[i];

        if i < N {
            func_body = quote {
                $func_body

                let i = $i;
                let len_i = lengths[i];
                assert(len_i >= $min_len_i, f"chunk {i} length below minimum");
                assert(len_i <= $max_len_i, f"chunk {i} length above maximum");

                for j in 0..$min_len_i {
                    buf[offset + j] = $chunk_i[j];
                }
                for j in $min_len_i..$max_len_i {
                    let is_active = j < len_i;
                    buf[offset + j] = if is_active { $chunk_i[j] } else { 0 };
                }
                offset += len_i;
            };
        }
    }

    let quote_buf = quote {
        | $params |
        {
            $func_body

            buf
        }
    };

    quote_buf
}

global ADD: str<3> = "add";
global DEL: str<3> = "del";

pub comptime fn concat_chunks_alt<let N: u32>(ranges: [(u32, u32); N]) -> Quoted {
    let min_len = ranges.map(|r| r.0);
    let max_len = ranges.map(|r| r.1);
    let out_len = max_len.reduce(|a, b| a + b);

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

    // Zero-pad the last chunk
    let last_index: u32 = (N - 1).as_();
    let last_chunk = f"chunk_{last_index}".quoted_contents();
    let last_chunk_len = out_len - add_positions[N - 1] - max_len[N - 1];

    // Header part
    let header_buf = quote {
        let mut buf = [0; $out_len];
        let mut head = [0; $N];
        let mut chunk_byte = [0; $N];

        // Zero-pad the last chunk
        let $last_chunk = $last_chunk.concat([0; $last_chunk_len]);

        for i in 0..$N - 1 {
            assert(len[i] >= $min_len[i], f"chunk {i} length below minimum");
            assert(len[i] <= $max_len[i], f"chunk {i} length above maximum");
        }
        
        head[0] = 0;
        assert(head[0] >= $add_positions[0], f"head[0] below add_positions[0]");
        assert(head[0] < $del_positions[0], f"head[0] above del_positions[0]");
        for i in 0..$N - 2 {
            head[i + 1] = head[i] + len[i];
            assert(head[i + 1] >= $add_positions[i + 1], f"head[{i} + 1] below add_positions[{i} + 1]");
            assert(head[i + 1] < $del_positions[i + 1], f"head[{i} + 1] above del_positions[{i} + 1]");
        }
        head[$N - 1] = head[$N - 2] + len[$N - 2];
        assert(head[$N - 1] >= $add_positions[$N - 1]);
    };

    // Inner part
    let mut inner_buf = quote {};
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

            cond_part = if operations.len() != 0 {
                quote {
                    $cond_part
                    in_chunk[$op] = acc_in_chunk & i < head[$op + 1];
                    acc_in_chunk &= !in_chunk[$op];
                }
            } else {
                // last operation
                quote {
                    $cond_part
                    in_chunk[$op] = acc_in_chunk;
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

    // Parameters part
    let mut params = quote {};
    for i in 0..N {
        let chunk_i = f"chunk_{i}".quoted_contents();
        let max_len_i = max_len[i];
        params = quote {
            $params
            $chunk_i: [u8; $max_len_i],
        };
    }
    params = quote {
        $params
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
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (4, 6)
    let chunk_0 = [1, 1, 1, 1, 0];
    let len_0 = 4;
    let chunk_1 = [2, 2, 2, 2, 2, 0];
    let len_1 = 5;

    let result = concat_chunks!([(2u32, 5u32), (4u32, 6u32)])(chunk_0, chunk_1, [len_0, len_1]);
    let expected = [1, 1, 1, 1, 2, 2, 2, 2, 2, 0, 0];
    assert_eq(result, expected);
}

#[test]
fn test_concat_chunks_2_dummy_suffix() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (4, 6)
    let chunk_0 = [1, 1, 1, 1, 127];
    let len_0 = 4;
    let chunk_1 = [2, 2, 2, 2, 2, 127];
    let len_1 = 5;

    let result = concat_chunks!([(2u32, 5u32), (4u32, 6u32)])(chunk_0, chunk_1, [len_0, len_1]);
    let expected = [1, 1, 1, 1, 2, 2, 2, 2, 2, 0, 0];
    assert_eq(result, expected);
}

#[test]
fn test_concat_chunks_alt_2() {
    let chunk_0 = [1, 1, 1, 1, 0];
    let len_0 = 4;
    let chunk_1 = [2, 2, 2, 2, 2, 0];

    let result = concat_chunks_alt!([(2u32, 5u32), (4u32, 6u32)])(chunk_0, chunk_1, [len_0]);
    let expected = [1, 1, 1, 1, 2, 2, 2, 2, 2, 0, 0];
    assert_eq(result, expected);
}

#[test]
fn test_concat_chunks_2_min_boundary() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (4, 6)
    let chunk_0 = [1, 1, 0, 0, 0];
    let len_0 = 2;
    let chunk_1 = [2, 2, 2, 2, 2, 0];
    let len_1 = 5;

    let result = concat_chunks!([(2u32, 5u32), (4u32, 6u32)])(chunk_0, chunk_1, [len_0, len_1]);
    let expected = [1, 1, 2, 2, 2, 2, 2, 0, 0, 0, 0];
    assert_eq(result, expected);
}

#[test]
fn test_concat_chunks_alt_2_min_boundary() {
    let chunk_0 = [1, 1, 0, 0, 0];
    let len_0 = 2;
    let chunk_1 = [2, 2, 2, 2, 2, 0];

    let result = concat_chunks_alt!([(2u32, 5u32), (4u32, 6u32)])(chunk_0, chunk_1, [len_0]);
    let expected = [1, 1, 2, 2, 2, 2, 2, 0, 0, 0, 0];
    assert_eq(result, expected);
}

#[test(should_fail_with = "chunk 0 length below minimum")]
fn test_concat_chunks_2_beyond_min_boundary() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (4, 6)
    let chunk_0 = [1, 0, 0, 0, 0];
    let len_0 = 1;
    let chunk_1 = [2, 2, 2, 2, 2, 127];
    let len_1 = 5;

    let _result = concat_chunks!([(2u32, 5u32), (4u32, 6u32)])(chunk_0, chunk_1, [len_0, len_1]);
}

#[test(should_fail_with = "chunk 0 length below minimum")]
fn test_concat_chunks_alt_2_beyond_min_boundary() {
    let chunk_0 = [1, 0, 0, 0, 0];
    let len_0 = 1;
    let chunk_1 = [2, 2, 2, 2, 2, 0];

    let _result = concat_chunks_alt!([(2u32, 5u32), (4u32, 6u32)])(chunk_0, chunk_1, [len_0]);
}

#[test]
fn test_concat_chunks_2_max_boundary() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (4, 6)
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 5;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 6;

    let result = concat_chunks!([(2u32, 5u32), (4u32, 6u32)])(chunk_0, chunk_1, [len_0, len_1]);
    let expected = [1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2];
    assert_eq(result, expected);
}

#[test]
fn test_concat_chunks_alt_2_max_boundary() {
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 5;
    let chunk_1 = [2, 2, 2, 2, 2, 2];

    let result = concat_chunks_alt!([(2u32, 5u32), (4u32, 6u32)])(chunk_0, chunk_1, [len_0]);
    let expected = [1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2];
    assert_eq(result, expected);
}

#[test(should_fail_with = "chunk 0 length above maximum")]
fn test_concat_chunks_2_beyond_max_boundary() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (4, 6)
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 6;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 6;

    let _result = concat_chunks!([(2u32, 5u32), (4u32, 6u32)])(chunk_0, chunk_1, [len_0, len_1]);
}

#[test(should_fail_with = "chunk 0 length above maximum")]
fn test_concat_chunks_alt_2_beyond_max_boundary() {
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 6;
    let chunk_1 = [2, 2, 2, 2, 2, 2];

    let _result = concat_chunks_alt!([(2u32, 5u32), (4u32, 6u32)])(chunk_0, chunk_1, [len_0]);
}

#[test]
fn test_concat_chunks_3() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (4, 6)
    // len range of chunk 2: (2, 3)
    let chunk_0 = [1, 1, 1, 1, 0];
    let len_0 = 4;
    let chunk_1 = [2, 2, 2, 2, 2, 0];
    let len_1 = 5;
    let chunk_2 = [3, 3, 0];
    let len_2 = 2;
    let result = concat_chunks!([(2u32, 5u32), (4u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1, len_2],
    );
    let expected = [1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 0, 0, 0];
    assert_eq(result, expected);
}

#[test]
fn test_concat_chunks_alt_3() {
    let chunk_0 = [1, 1, 1, 1, 0];
    let len_0 = 4;
    let chunk_1 = [2, 2, 2, 2, 2, 0];
    let len_1 = 5;
    let chunk_2 = [3, 3, 0];
    let result = concat_chunks_alt!([(2u32, 5u32), (4u32, 6u32), (2u32, 3u32)])(
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
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (4, 6)
    // len range of chunk 2: (2, 3)
    let chunk_0 = [1, 1, 0, 0, 0];
    let len_0 = 2;
    let chunk_1 = [2, 2, 2, 2, 0, 0];
    let len_1 = 4;
    let chunk_2 = [3, 3, 0];
    let len_2 = 2;
    let result = concat_chunks!([(2u32, 5u32), (4u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1, len_2],
    );
    let expected = [1, 1, 2, 2, 2, 2, 3, 3, 0, 0, 0, 0, 0, 0];
    assert_eq(result, expected);
}

#[test]
fn test_concat_chunks_alt_3_min_boundary() {
    let chunk_0 = [1, 1, 0, 0, 0];
    let len_0 = 2;
    let chunk_1 = [2, 2, 2, 2, 0, 0];
    let len_1 = 4;
    let chunk_2 = [3, 3, 0];
    let result = concat_chunks_alt!([(2u32, 5u32), (4u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
    let expected = [1, 1, 2, 2, 2, 2, 3, 3, 0, 0, 0, 0, 0, 0];
    assert_eq(result, expected);
}

#[test(should_fail_with = "chunk 0 length below minimum")]
fn test_concat_chunks_3_beyond_min_boundary_0() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (4, 6)
    // len range of chunk 2: (2, 3)
    let chunk_0 = [1, 0, 0, 0, 0];
    let len_0 = 1;
    let chunk_1 = [2, 2, 2, 2, 0, 0];
    let len_1 = 4;
    let chunk_2 = [3, 3, 0];
    let len_2 = 2;
    let _result = concat_chunks!([(2u32, 5u32), (4u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1, len_2],
    );
}

#[test(should_fail_with = "chunk 0 length below minimum")]
fn test_concat_chunks_alt_3_beyond_min_boundary_0() {
    let chunk_0 = [1, 0, 0, 0, 0];
    let len_0 = 1;
    let chunk_1 = [2, 2, 2, 2, 0, 0];
    let len_1 = 4;
    let chunk_2 = [3, 3, 0];
    let _result = concat_chunks_alt!([(2u32, 5u32), (4u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
}

#[test(should_fail_with = "chunk 1 length below minimum")]
fn test_concat_chunks_3_beyond_min_boundary_1() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (4, 6)
    // len range of chunk 2: (2, 3)
    let chunk_0 = [1, 1, 0, 0, 0];
    let len_0 = 2;
    let chunk_1 = [2, 2, 2, 0, 0, 0];
    let len_1 = 3;
    let chunk_2 = [3, 3, 0];
    let len_2 = 2;
    let _result = concat_chunks!([(2u32, 5u32), (4u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1, len_2],
    );
}

#[test(should_fail_with = "chunk 1 length below minimum")]
fn test_concat_chunks_alt_3_beyond_min_boundary_1() {
    let chunk_0 = [1, 1, 0, 0, 0];
    let len_0 = 2;
    let chunk_1 = [2, 2, 2, 0, 0, 0];
    let len_1 = 3;
    let chunk_2 = [3, 3, 0];
    let _result = concat_chunks_alt!([(2u32, 5u32), (4u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
}

#[test]
fn test_concat_chunks_3_max_boundary() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (4, 6)
    // len range of chunk 2: (2, 3)
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 5;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 6;
    let chunk_2 = [3, 3, 3];
    let len_2 = 3;
    let result = concat_chunks!([(2u32, 5u32), (4u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1, len_2],
    );
    let expected = [1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3];
    assert_eq(result, expected);
}

#[test]
fn test_concat_chunks_alt_3_max_boundary() {
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 5;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 6;
    let chunk_2 = [3, 3, 3];
    let result = concat_chunks_alt!([(2u32, 5u32), (4u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
    let expected = [1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3];
    assert_eq(result, expected);
}

#[test(should_fail_with = "chunk 0 length above maximum")]
fn test_concat_chunks_3_beyond_max_boundary_0() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (4, 6)
    // len range of chunk 2: (2, 3)
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 6;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 6;
    let chunk_2 = [3, 3, 3];
    let len_2 = 3;
    let _result = concat_chunks!([(2u32, 5u32), (4u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1, len_2],
    );
}

#[test(should_fail_with = "chunk 0 length above maximum")]
fn test_concat_chunks_alt_3_beyond_max_boundary_0() {
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 6;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 6;
    let chunk_2 = [3, 3, 3];
    let _result = concat_chunks_alt!([(2u32, 5u32), (4u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
}

#[test(should_fail_with = "chunk 1 length above maximum")]
fn test_concat_chunks_3_beyond_max_boundary_1() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (4, 6)
    // len range of chunk 2: (2, 3)
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 5;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 7;
    let chunk_2 = [3, 3, 3];
    let len_2 = 3;
    let _result = concat_chunks!([(2u32, 5u32), (4u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1, len_2],
    );
}

#[test(should_fail_with = "chunk 1 length above maximum")]
fn test_concat_chunks_alt_3_beyond_max_boundary_1() {
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 5;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 7;
    let chunk_2 = [3, 3, 3];
    let _result = concat_chunks_alt!([(2u32, 5u32), (4u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
}

#[test]
fn test_concat_chunks_3_2() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (2, 6)
    // len range of chunk 2: (2, 3)
    let chunk_0 = [1, 1, 1, 1, 0];
    let len_0 = 4;
    let chunk_1 = [2, 2, 2, 2, 2, 0];
    let len_1 = 5;
    let chunk_2 = [3, 3, 0];
    let len_2 = 2;
    let result = concat_chunks!([(2u32, 5u32), (2u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1, len_2],
    );
    let expected = [1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 0, 0, 0];
    assert_eq(result, expected);
}

#[test]
fn test_concat_chunks_alt_3_2() {
    let chunk_0 = [1, 1, 1, 1, 0];
    let len_0 = 4;
    let chunk_1 = [2, 2, 2, 2, 2, 0];
    let len_1 = 5;
    let chunk_2 = [3, 3, 0];
    let result = concat_chunks_alt!([(2u32, 5u32), (2u32, 6u32), (2u32, 3u32)])(
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
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (2, 6)
    // len range of chunk 2: (2, 3)
    let chunk_0 = [1, 1, 0, 0, 0];
    let len_0 = 2;
    let chunk_1 = [2, 2, 0, 0, 0, 0];
    let len_1 = 2;
    let chunk_2 = [3, 3, 0];
    let len_2 = 2;
    let result = concat_chunks!([(2u32, 5u32), (2u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1, len_2],
    );
    let expected = [1, 1, 2, 2, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq(result, expected);
}

#[test]
fn test_concat_chunks_alt_3_2_min_boundary() {
    let chunk_0 = [1, 1, 0, 0, 0];
    let len_0 = 2;
    let chunk_1 = [2, 2, 0, 0, 0, 0];
    let len_1 = 2;
    let chunk_2 = [3, 3, 0];
    let result = concat_chunks_alt!([(2u32, 5u32), (2u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
    let expected = [1, 1, 2, 2, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq(result, expected);
}

#[test(should_fail_with = "chunk 0 length below minimum")]
fn test_concat_chunks_3_2_beyond_min_boundary_0() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (2, 6)
    // len range of chunk 2: (2, 3)
    let chunk_0 = [1, 0, 0, 0, 0];
    let len_0 = 1;
    let chunk_1 = [2, 2, 2, 2, 0, 0];
    let len_1 = 4;
    let chunk_2 = [3, 3, 0];
    let len_2 = 2;
    let _result = concat_chunks!([(2u32, 5u32), (2u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1, len_2],
    );
}

#[test(should_fail_with = "chunk 0 length below minimum")]
fn test_concat_chunks_alt_3_2_beyond_min_boundary_0() {
    let chunk_0 = [1, 0, 0, 0, 0];
    let len_0 = 1;
    let chunk_1 = [2, 2, 2, 2, 0, 0];
    let len_1 = 4;
    let chunk_2 = [3, 3, 0];
    let _result = concat_chunks_alt!([(2u32, 5u32), (2u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
}

#[test(should_fail_with = "chunk 1 length below minimum")]
fn test_concat_chunks_3_2_beyond_min_boundary_1() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (2, 6)
    // len range of chunk 2: (2, 3)
    let chunk_0 = [1, 1, 0, 0, 0];
    let len_0 = 2;
    let chunk_1 = [2, 0, 0, 0, 0, 0];
    let len_1 = 1;
    let chunk_2 = [3, 3, 0];
    let len_2 = 2;
    let _result = concat_chunks!([(2u32, 5u32), (2u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1, len_2],
    );
}

#[test(should_fail_with = "chunk 1 length below minimum")]
fn test_concat_chunks_alt_3_2_beyond_min_boundary_1() {
    let chunk_0 = [1, 1, 0, 0, 0];
    let len_0 = 2;
    let chunk_1 = [2, 0, 0, 0, 0, 0];
    let len_1 = 1;
    let chunk_2 = [3, 3, 0];
    let _result = concat_chunks_alt!([(2u32, 5u32), (2u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
}

#[test]
fn test_concat_chunks_3_2_max_boundary() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (2, 6)
    // len range of chunk 2: (2, 3)
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 5;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 6;
    let chunk_2 = [3, 3, 3];
    let len_2 = 3;
    let result = concat_chunks!([(2u32, 5u32), (2u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1, len_2],
    );
    let expected = [1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3];
    assert_eq(result, expected);
}

#[test]
fn test_concat_chunks_alt_3_2_max_boundary() {
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 5;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 6;
    let chunk_2 = [3, 3, 3];
    let result = concat_chunks_alt!([(2u32, 5u32), (2u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
    let expected = [1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3];
    assert_eq(result, expected);
}

#[test(should_fail_with = "chunk 0 length above maximum")]
fn test_concat_chunks_3_2_beyond_max_boundary_0() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (2, 6)
    // len range of chunk 2: (2, 3)
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 6;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 6;
    let chunk_2 = [3, 3, 3];
    let len_2 = 3;
    let _result = concat_chunks!([(2u32, 5u32), (2u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1, len_2],
    );
}

#[test(should_fail_with = "chunk 0 length above maximum")]
fn test_concat_chunks_alt_3_2_beyond_max_boundary_0() {
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 6;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 6;
    let chunk_2 = [3, 3, 3];
    let _result = concat_chunks_alt!([(2u32, 5u32), (2u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
}

#[test(should_fail_with = "chunk 1 length above maximum")]
fn test_concat_chunks_3_2_beyond_max_boundary_1() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (2, 6)
    // len range of chunk 2: (2, 3)
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 5;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 7;
    let chunk_2 = [3, 3, 3];
    let len_2 = 3;
    let _result = concat_chunks!([(2u32, 5u32), (2u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1, len_2],
    );
}

#[test(should_fail_with = "chunk 1 length above maximum")]
fn test_concat_chunks_alt_3_2_beyond_max_boundary_1() {
    let chunk_0 = [1, 1, 1, 1, 1];
    let len_0 = 5;
    let chunk_1 = [2, 2, 2, 2, 2, 2];
    let len_1 = 7;
    let chunk_2 = [3, 3, 3];
    let _result = concat_chunks_alt!([(2u32, 5u32), (2u32, 6u32), (2u32, 3u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
}

#[test]
fn test_concat_chunks_4() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (4, 6)
    // len range of chunk 2: (2, 3)
    // len range of chunk 3: (3, 5)
    let chunk_0 = [1, 1, 1, 1, 0];
    let len_0 = 4;
    let chunk_1 = [2, 2, 2, 2, 2, 0];
    let len_1 = 5;
    let chunk_2 = [3, 3, 0];
    let len_2 = 2;
    let chunk_3 = [4, 4, 4, 4, 0];
    let len_3 = 4;
    let result = concat_chunks!([(2u32, 5u32), (4u32, 6u32), (2u32, 3u32), (3u32, 5u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        chunk_3,
        [len_0, len_1, len_2, len_3],
    );
    let expected = [1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 4, 4, 4, 4, 0, 0, 0, 0];
    assert_eq(result, expected);
}

#[test]
fn test_concat_chunks_4_dummy_suffix() {
    // len range of chunk 0: (2, 5)
    // len range of chunk 1: (4, 6)
    // len range of chunk 2: (2, 3)
    // len range of chunk 3: (3, 5)
    let chunk_0 = [1, 1, 1, 1, 127];
    let len_0 = 4;
    let chunk_1 = [2, 2, 2, 2, 2, 127];
    let len_1 = 5;
    let chunk_2 = [3, 3, 127];
    let len_2 = 2;
    let chunk_3 = [4, 4, 4, 4, 127];
    let len_3 = 4;
    let result = concat_chunks!([(2u32, 5u32), (4u32, 6u32), (2u32, 3u32), (3u32, 5u32)])(
        chunk_0,
        chunk_1,
        chunk_2,
        chunk_3,
        [len_0, len_1, len_2, len_3],
    );
    let expected = [1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 4, 4, 4, 4, 0, 0, 0, 0];
    assert_eq(result, expected);
}
