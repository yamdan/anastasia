use std::convert::AsPrimitive;

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

global ADD: str<3> = "add";
global DEL: str<3> = "del";

pub comptime fn meta_concat_chunks<let N: u32>(
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

pub comptime fn meta_concat_chunks_3(
    min_len_0: u32,
    max_len_0: u32,
    min_len_1: u32,
    max_len_1: u32,
    out_len: u32,
) -> Quoted {
    let ADD_1: u32 = min_len_0;
    let ADD_2: u32 = ADD_1 + min_len_1;
    let DEL_0: u32 = max_len_0;
    let DEL_1: u32 = DEL_0 + max_len_1;

    assert(min_len_0 <= max_len_0, "min_len_0 must be <= max_len_0");
    assert(min_len_1 <= max_len_1, "min_len_1 must be <= max_len_1");
    assert(DEL_1 <= out_len, "max_len_0 + max_len_1 must be <= out_len");

    let arr = [(ADD_1, (ADD, 1)), (ADD_2, (ADD, 2)), (DEL_0, (DEL, 0)), (DEL_1, (DEL, 1))];
    let sorted_arr = arr.sort_via(|a, b| a.0 < b.0);

    let mut buf = Vec::from_slice(&[0]);
    let mut sequences = Vec::new();
    let mut from_index = 0;
    for inst in sorted_arr {
        let to_index = inst.0;
        let action = inst.1;
        sequences.push(((from_index, to_index), buf));

        if action.0 == ADD {
            buf.push(action.1);
        } else {
            let _ = buf.remove(0);
        }
        from_index = to_index;
    }
    sequences.push(((from_index, out_len), buf));

    let mut inner_buf = quote {
        let mut buf: [u8; $out_len] = [0; $out_len];
        let mut acc_len: [u32; 4] = [0; 4];
        let mut chunk_byte: [u8; 3] = [0; 3];

        acc_len[0] = 0;
        acc_len[1] = len_0;
        acc_len[2] = acc_len[1] + len_1;

        assert(acc_len[1] >= $min_len_0);
        assert(acc_len[1] <= $max_len_0);
        assert(acc_len[2] >= $min_len_0 + $min_len_1);
        assert(acc_len[2] <= $max_len_0 + $max_len_1);
    };
    loop {
        let sequence = sequences.remove(0);
        let range = sequence.0;
        let mut operations = sequence.1;

        let mut cond_part = quote {
            let mut in_chunk: [bool; 3] = [false; 3];
            let mut acc_in_chunk = true;
        };
        let mut byte_part = quote {};

        loop {
            let op = operations.remove(0);

            cond_part = if operations.len() == 0 {
                quote {
                    $cond_part
                    in_chunk[$op] = acc_in_chunk;
                }
            } else {
                quote {
                    $cond_part
                    in_chunk[$op] = acc_in_chunk & i < acc_len[$op + 1];
                    acc_in_chunk &= !in_chunk[$op];
                }
            };

            let op32: u32 = op.as_();
            let bytes = f"chunk_{op32}_bytes".quoted_contents();
            byte_part = quote {
                $byte_part

                chunk_byte[$op] = if in_chunk[$op] {
                    $bytes[i - acc_len[$op]]
                } else {
                    0
                };

                buf[i] += chunk_byte[$op];
            };

            if operations.len() == 0 { break };
        }

        inner_buf = quote {
            $inner_buf

            for i in $range.0..$range.1 {
                $cond_part

                $byte_part
            }
        };

        if sequences.len() == 0 {
            break;
        }
    }

    let quote_buf = quote {
        |
            chunk_0_bytes: [u8; $max_len_0],
            len_0: u32,
            chunk_1_bytes: [u8; $max_len_1],
            len_1: u32,
            chunk_2_bytes: [u8; $out_len - $min_len_0 - $min_len_1],
        |
        {
            $inner_buf

            buf
        }
    };

    quote_buf
}

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

#[test]
fn test_meta_concat_chunks_3() { 
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
    let result = meta_concat_chunks_3!(2u32, 5u32, 4u32, 6u32, 14u32)(
        chunk_0,
        len_0,
        chunk_1,
        len_1,
        chunk_2,
    );
    let expected = [1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 0, 0, 0];
    assert_eq(result, expected);
}

#[test]
fn test_meta_concat_chunks_3_min_boundary() {
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
    let result = meta_concat_chunks_3!(2u32, 5u32, 4u32, 6u32, 14u32)(
        chunk_0,
        len_0,
        chunk_1,
        len_1,
        chunk_2,
    );
    let expected = [1, 1, 2, 2, 2, 2, 3, 3, 0, 0, 0, 0, 0, 0];
    assert_eq(result, expected);
}

#[test(should_fail_with = "Failed constraint")]
fn test_meta_concat_chunks_3_beyond_min_boundary_0() {
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
    let _result = meta_concat_chunks_3!(2u32, 5u32, 4u32, 6u32, 14u32)(
        chunk_0,
        len_0,
        chunk_1,
        len_1,
        chunk_2,
    );
}

#[test(should_fail_with = "Failed constraint")]
fn test_meta_concat_chunks_3_beyond_min_boundary_1() {
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
    let _result = meta_concat_chunks_3!(2u32, 5u32, 4u32, 6u32, 14u32)(
        chunk_0,
        len_0,
        chunk_1,
        len_1,
        chunk_2,
    );
}

#[test]
fn test_meta_concat_chunks_3_max_boundary() {
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
    let result = meta_concat_chunks_3!(2u32, 5u32, 4u32, 6u32, 14u32)(
        chunk_0,
        len_0,
        chunk_1,
        len_1,
        chunk_2,
    );
    let expected = [1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3];
    assert_eq(result, expected);
}

#[test(should_fail_with = "Failed constraint")]
fn test_meta_concat_chunks_3_beyond_max_boundary_0() {
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
    let _result = meta_concat_chunks_3!(2u32, 5u32, 4u32, 6u32, 14u32)(
        chunk_0,
        len_0,
        chunk_1,
        len_1,
        chunk_2,
    );
}

#[test(should_fail_with = "Failed constraint")]
fn test_meta_concat_chunks_3_beyond_max_boundary_1() {
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
    let _result = meta_concat_chunks_3!(2u32, 5u32, 4u32, 6u32, 14u32)(
        chunk_0,
        len_0,
        chunk_1,
        len_1,
        chunk_2,
    );
}

#[test]
fn test_meta_concat_chunks_3_2() {
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
    let result = meta_concat_chunks_3!(2u32, 5u32, 2u32, 6u32, 14u32)(
        chunk_0,
        len_0,
        chunk_1,
        len_1,
        chunk_2,
    );
    let expected = [1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 0, 0, 0];
    assert_eq(result, expected);
}

#[test]
fn test_meta_concat_chunks_3_2_min_boundary() {
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
    let result = meta_concat_chunks_3!(2u32, 5u32, 2u32, 6u32, 14u32)(
        chunk_0,
        len_0,
        chunk_1,
        len_1,
        chunk_2,
    );
    let expected = [1, 1, 2, 2, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq(result, expected);
}

#[test(should_fail_with = "Failed constraint")]
fn test_meta_concat_chunks_3_2_beyond_min_boundary_0() {
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
    let _result = meta_concat_chunks_3!(2u32, 5u32, 2u32, 6u32, 14u32)(
        chunk_0,
        len_0,
        chunk_1,
        len_1,
        chunk_2,
    );
}

#[test(should_fail_with = "Failed constraint")]
fn test_meta_concat_chunks_3_2_beyond_min_boundary_1() {
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
    let _result = meta_concat_chunks_3!(2u32, 5u32, 2u32, 6u32, 14u32)(
        chunk_0,
        len_0,
        chunk_1,
        len_1,
        chunk_2,
    );
}

#[test]
fn test_meta_concat_chunks_3_2_max_boundary() {
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
    let result = meta_concat_chunks_3!(2u32, 5u32, 2u32, 6u32, 14u32)(
        chunk_0,
        len_0,
        chunk_1,
        len_1,
        chunk_2,
    );
    let expected = [1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3];
    assert_eq(result, expected);
}

#[test(should_fail_with = "Failed constraint")]
fn test_meta_concat_chunks_3_2_beyond_max_boundary_0() {
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
    let _result = meta_concat_chunks_3!(2u32, 5u32, 2u32, 6u32, 14u32)(
        chunk_0,
        len_0,
        chunk_1,
        len_1,
        chunk_2,
    );
}

#[test(should_fail_with = "Failed constraint")]
fn test_meta_concat_chunks_3_2_beyond_max_boundary_1() {
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
    let _result = meta_concat_chunks_3!(2u32, 5u32, 2u32, 6u32, 14u32)(
        chunk_0,
        len_0,
        chunk_1,
        len_1,
        chunk_2,
    );
}

#[test]
fn test_meta_concat_chunks_3_N() {
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
    let result = meta_concat_chunks!([2u32, 4u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
    let expected = [1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 0, 0, 0];
    assert_eq(result, expected);
}

#[test]
fn test_concat_chunks_3_N_min_boundary() {
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
    let result = meta_concat_chunks!([2u32, 4u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
    let expected = [1, 1, 2, 2, 2, 2, 3, 3, 0, 0, 0, 0, 0, 0];
    assert_eq(result, expected);
}

#[test(should_fail_with = "Failed constraint")]
fn test_concat_chunks_3_N_beyond_min_boundary_0() {
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
    let _result = meta_concat_chunks!([2u32, 4u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
}

#[test(should_fail_with = "Failed constraint")]
fn test_concat_chunks_3_N_beyond_min_boundary_1() {
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
    let _result = meta_concat_chunks!([2u32, 4u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
}

#[test]
fn test_concat_chunks_3_N_max_boundary() {
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
    let result = meta_concat_chunks!([2u32, 4u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
    let expected = [1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3];
    assert_eq(result, expected);
}

#[test(should_fail_with = "Failed constraint")]
fn test_concat_chunks_3_N_beyond_max_boundary_0() {
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
    let _result = meta_concat_chunks!([2u32, 4u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
}

#[test(should_fail_with = "Failed constraint")]
fn test_concat_chunks_3_N_beyond_max_boundary_1() {
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
    let _result = meta_concat_chunks!([2u32, 4u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
}

#[test]
fn test_concat_chunks_3_2_N() {
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
    let result = meta_concat_chunks!([2u32, 2u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
    let expected = [1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 0, 0, 0];
    assert_eq(result, expected);
}

#[test]
fn test_concat_chunks_3_2_N_min_boundary() {
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
    let result = meta_concat_chunks!([2u32, 2u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
    let expected = [1, 1, 2, 2, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq(result, expected);
}

#[test(should_fail_with = "Failed constraint")]
fn test_concat_chunks_3_2_N_beyond_min_boundary_0() {
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
    let _result = meta_concat_chunks!([2u32, 2u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
}

#[test(should_fail_with = "Failed constraint")]
fn test_concat_chunks_3_2_N_beyond_min_boundary_1() {
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
    let _result = meta_concat_chunks!([2u32, 2u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
}

#[test]
fn test_concat_chunks_3_2_N_max_boundary() {
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
    let result = meta_concat_chunks!([2u32, 2u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
    let expected = [1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3];
    assert_eq(result, expected);
}

#[test(should_fail_with = "Failed constraint")]
fn test_concat_chunks_3_2_N_beyond_max_boundary_0() {
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
    let _result = meta_concat_chunks!([2u32, 2u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
}

#[test(should_fail_with = "Failed constraint")]
fn test_concat_chunks_3_2_N_beyond_max_boundary_1() {
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
    let _result = meta_concat_chunks!([2u32, 2u32], [5u32, 6u32], 14u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        [len_0, len_1],
    );
}

#[test]
fn test_meta_concat_chunks_4_N() {
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
    let result = meta_concat_chunks!([2u32, 4u32, 2u32], [5u32, 6u32, 3u32], 16u32)(
        chunk_0,
        chunk_1,
        chunk_2,
        chunk_3,
        [len_0, len_1, len_2],
    );
    let expected = [1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 4, 4, 4, 4, 0];
    assert_eq(result, expected);
}
