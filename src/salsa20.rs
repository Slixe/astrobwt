const BLOCK_SIZE: usize = 64;
const COUNTER_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const CONSTANT_SIZE: usize = 16;
const SIGMA: [u8; CONSTANT_SIZE] = [
    b'e', b'x', b'p', b'a', b'n', b'd', b' ', b'3', b'2', b'-', b'b', b'y', b't', b'e', b' ', b'k',
];
const ROUNDS: usize = 20;

pub fn xor_key_stream(mut output: &mut [u8], mut input: &[u8], key: &[u8; KEY_SIZE]) {
    let mut block = [0u8; BLOCK_SIZE];
    let mut counter = [0u8; COUNTER_SIZE];

    while input.len() >= BLOCK_SIZE {
        core(&mut block, &mut counter, &key, &SIGMA);
        for (i, x) in block.iter().enumerate() {
            output[i] = input[i] ^ x;
        }

        let mut u = 1u32;
        for i in 8..16 {
            u += counter[i] as u32;
            counter[i] = u as u8;
            u >>= 8;
        }
        input = &input[64..];
        output = &mut output[64..];
    }

    if input.len() > 0 {
        core(&mut block, &mut counter, &key, &SIGMA);
        for (i, v) in input.iter().enumerate() {
            output[i] = v ^ block[i];
        }
    }
}

fn core(
    output: &mut [u8; BLOCK_SIZE],
    input: &[u8; COUNTER_SIZE],
    k: &[u8; KEY_SIZE],
    c: &[u8; CONSTANT_SIZE],
) {
    let j0 = c[0] as u32 | (c[1] as u32) << 8 | (c[2] as u32) << 16 | (c[3] as u32) << 24;
    let j1 = k[0] as u32 | (k[1] as u32) << 8 | (k[2] as u32) << 16 | (k[3] as u32) << 24;
    let j2 = k[4] as u32 | (k[5] as u32) << 8 | (k[6] as u32) << 16 | (k[7] as u32) << 24;
    let j3 = k[8] as u32 | (k[9] as u32) << 8 | (k[10] as u32) << 16 | (k[11] as u32) << 24;
    let j4 = k[12] as u32 | (k[13] as u32) << 8 | (k[14] as u32) << 16 | (k[15] as u32) << 24;
    let j5 = c[4] as u32 | (c[5] as u32) << 8 | (c[6] as u32) << 16 | (c[7] as u32) << 24;
    let j6 = input[0] as u32 | (input[1] as u32) << 8 | (input[2] as u32) << 16 | (input[3] as u32) << 24;
    let j7 = input[4] as u32 | (input[5] as u32) << 8 | (input[6] as u32) << 16 | (input[7] as u32) << 24;
    let j8 = input[8] as u32 | (input[9] as u32) << 8 | (input[10] as u32) << 16 | (input[11] as u32) << 24;
    let j9 = input[12] as u32| (input[13] as u32) << 8 | (input[14] as u32) << 16 | (input[15] as u32) << 24;
    let j10 = c[8] as u32 | (c[9] as u32) << 8 | (c[10] as u32) << 16 | (c[11] as u32) << 24;
    let j11 = k[16] as u32 | (k[17] as u32) << 8 | (k[18] as u32) << 16 | (k[19] as u32) << 24;
    let j12 = k[20] as u32 | (k[21] as u32) << 8 | (k[22] as u32) << 16 | (k[23] as u32) << 24;
    let j13 = k[24] as u32 | (k[25] as u32) << 8 | (k[26] as u32) << 16 | (k[27] as u32) << 24;
    let j14 = k[28] as u32 | (k[29] as u32) << 8 | (k[30] as u32) << 16 | (k[31] as u32) << 24;
    let j15 = c[12] as u32 | (c[13] as u32) << 8 | (c[14] as u32) << 16 | (c[15] as u32) << 24;

    let (mut x0, mut x1, mut x2, mut x3, mut x4, mut x5, mut x6, mut x7, mut x8) =
        (j0, j1, j2, j3, j4, j5, j6, j7, j8);
    let (mut x9, mut x10, mut x11, mut x12, mut x13, mut x14, mut x15) =
        (j9, j10, j11, j12, j13, j14, j15);

    let mut i = 0;
    while i < ROUNDS {
        let mut u: u32 = u32::wrapping_add(x0, x12);
        x4 ^= u << 7 | u >> (32 - 7);
        u = u32::wrapping_add(x4, x0);
        x8 ^= u << 9 | u >> (32 - 9);
        u = u32::wrapping_add(x8, x4);
        x12 ^= u << 13 | u >> (32 - 13);
        u = u32::wrapping_add(x12, x8);
        x0 ^= u << 18 | u >> (32 - 18);

        u = u32::wrapping_add(x5, x1);
        x9 ^= u << 7 | u >> (32 - 7);
        u = u32::wrapping_add(x9, x5);
        x13 ^= u << 9 | u >> (32 - 9);
        u = u32::wrapping_add(x13, x9);
        x1 ^= u << 13 | u >> (32 - 13);
        u = u32::wrapping_add(x1, x13);
        x5 ^= u << 18 | u >> (32 - 18);

        u = u32::wrapping_add(x10, x6);
        x14 ^= u << 7 | u >> (32 - 7);
        u = u32::wrapping_add(x14, x10);
        x2 ^= u << 9 | u >> (32 - 9);
        u = u32::wrapping_add(x2, x14);
        x6 ^= u << 13 | u >> (32 - 13);
        u = u32::wrapping_add(x6, x2);
        x10 ^= u << 18 | u >> (32 - 18);

        u = u32::wrapping_add(x15, x11);
        x3 ^= u << 7 | u >> (32 - 7);
        u = u32::wrapping_add(x3, x15);
        x7 ^= u << 9 | u >> (32 - 9);
        u = u32::wrapping_add(x7, x3);
        x11 ^= u << 13 | u >> (32 - 13);
        u = u32::wrapping_add(x11, x7);
        x15 ^= u << 18 | u >> (32 - 18);

        u = u32::wrapping_add(x0, x3);
        x1 ^= u << 7 | u >> (32 - 7);
        u = u32::wrapping_add(x1, x0);
        x2 ^= u << 9 | u >> (32 - 9);
        u = u32::wrapping_add(x2, x1);
        x3 ^= u << 13 | u >> (32 - 13);
        u = u32::wrapping_add(x3, x2);
        x0 ^= u << 18 | u >> (32 - 18);

        u = u32::wrapping_add(x5, x4);
        x6 ^= u << 7 | u >> (32 - 7);
        u = u32::wrapping_add(x6, x5);
        x7 ^= u << 9 | u >> (32 - 9);
        u = u32::wrapping_add(x7, x6);
        x4 ^= u << 13 | u >> (32 - 13);
        u = u32::wrapping_add(x4, x7);
        x5 ^= u << 18 | u >> (32 - 18);

        u = u32::wrapping_add(x10, x9);
        x11 ^= u << 7 | u >> (32 - 7);
        u = u32::wrapping_add(x11, x10);
        x8 ^= u << 9 | u >> (32 - 9);
        u = u32::wrapping_add(x8, x11);
        x9 ^= u << 13 | u >> (32 - 13);
        u = u32::wrapping_add(x9, x8);
        x10 ^= u << 18 | u >> (32 - 18);

        u = u32::wrapping_add(x15, x14);
        x12 ^= u << 7 | u >> (32 - 7);
        u = u32::wrapping_add(x12, x15);
        x13 ^= u << 9 | u >> (32 - 9);
        u = u32::wrapping_add(x13, x12);
        x14 ^= u << 13 | u >> (32 - 13);
        u = u32::wrapping_add(x14, x13);
        x15 ^= u << 18 | u >> (32 - 18);

        i += 2;
    }

    x0 = u32::wrapping_add(x0, j0);
    x1 = u32::wrapping_add(x1, j1);
    x2 = u32::wrapping_add(x2, j2);
    x3 = u32::wrapping_add(x3, j3);
    x4 = u32::wrapping_add(x4, j4);
    x5 = u32::wrapping_add(x5, j5);
    x6 = u32::wrapping_add(x6, j6);
    x7 = u32::wrapping_add(x7, j7);
    x8 = u32::wrapping_add(x8, j8);
    x9 = u32::wrapping_add(x9, j9);
    x10 = u32::wrapping_add(x10, j10);
    x11 = u32::wrapping_add(x11, j11);
    x12 = u32::wrapping_add(x12, j12);
    x13 = u32::wrapping_add(x13, j13);
    x14 = u32::wrapping_add(x14, j14);
    x15 = u32::wrapping_add(x15, j15);

    output[0] = x0 as u8;
    output[1] = (x0 >> 8) as u8;
    output[2] = (x0 >> 16) as u8;
    output[3] = (x0 >> 24) as u8;

    output[4] = x1 as u8;
    output[5] = (x1 >> 8) as u8;
    output[6] = (x1 >> 16) as u8;
    output[7] = (x1 >> 24) as u8;

    output[8] = x2 as u8;
    output[9] = (x2 >> 8) as u8;
    output[10] = (x2 >> 16) as u8;
    output[11] = (x2 >> 24) as u8;

    output[12] = x3 as u8;
    output[13] = (x3 >> 8) as u8;
    output[14] = (x3 >> 16) as u8;
    output[15] = (x3 >> 24) as u8;

    output[16] = x4 as u8;
    output[17] = (x4 >> 8) as u8;
    output[18] = (x4 >> 16) as u8;
    output[19] = (x4 >> 24) as u8;

    output[20] = x5 as u8;
    output[21] = (x5 >> 8) as u8;
    output[22] = (x5 >> 16) as u8;
    output[23] = (x5 >> 24) as u8;

    output[24] = x6 as u8;
    output[25] = (x6 >> 8) as u8;
    output[26] = (x6 >> 16) as u8;
    output[27] = (x6 >> 24) as u8;

    output[28] = x7 as u8;
    output[29] = (x7 >> 8) as u8;
    output[30] = (x7 >> 16) as u8;
    output[31] = (x7 >> 24) as u8;

    output[32] = x8 as u8;
    output[33] = (x8 >> 8) as u8;
    output[34] = (x8 >> 16) as u8;
    output[35] = (x8 >> 24) as u8;

    output[36] = x9 as u8;
    output[37] = (x9 >> 8) as u8;
    output[38] = (x9 >> 16) as u8;
    output[39] = (x9 >> 24) as u8;

    output[40] = x10 as u8;
    output[41] = (x10 >> 8) as u8;
    output[42] = (x10 >> 16) as u8;
    output[43] = (x10 >> 24) as u8;

    output[44] = x11 as u8;
    output[45] = (x11 >> 8) as u8;
    output[46] = (x11 >> 16) as u8;
    output[47] = (x11 >> 24) as u8;

    output[48] = x12 as u8;
    output[49] = (x12 >> 8) as u8;
    output[50] = (x12 >> 16) as u8;
    output[51] = (x12 >> 24) as u8;

    output[52] = x13 as u8;
    output[53] = (x13 >> 8) as u8;
    output[54] = (x13 >> 16) as u8;
    output[55] = (x13 >> 24) as u8;

    output[56] = x14 as u8;
    output[57] = (x14 >> 8) as u8;
    output[58] = (x14 >> 16) as u8;
    output[59] = (x14 >> 24) as u8;

    output[60] = x15 as u8;
    output[61] = (x15 >> 8) as u8;
    output[62] = (x15 >> 16) as u8;
    output[63] = (x15 >> 24) as u8;
}
