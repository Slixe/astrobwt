use byteorder::{BigEndian, ByteOrder, LittleEndian};
use sha3::{Digest, Sha3_256};

const STAGE1_LENGTH: usize = 147253;
const COUNTING_SORT_BITS: u64 = 10;
const COUNTING_SORT_SIZE: u64 = 1 << COUNTING_SORT_BITS;
pub const MAX_LENGTH: usize = 1024 * 1024 + STAGE1_LENGTH + 1024;

pub fn compute(input: &[u8], max_limit: usize) -> Vec<u8> {
    let mut key = sha3(&input); // Step 1: calculate SHA3 of input data
    let mut stage1 = [0u8; STAGE1_LENGTH + 64];
    crate::salsa20::xor_key_stream(&mut stage1[1..STAGE1_LENGTH + 1], &[0u8; STAGE1_LENGTH], &key); // Step 2: expand data using Salsa20
    let mut stage1_result = [0u8; STAGE1_LENGTH + 1];
    sort_indices(STAGE1_LENGTH + 1, &mut stage1, &mut stage1_result); // Step 3: calculate BWT of step 2
    key = sha3(&stage1_result); // Step 4: calculate SHA3 of BWT data

    let stage2_length = STAGE1_LENGTH + (LittleEndian::read_u32(&key) & 0xfffff) as usize; // Step 5: calculate size of stage2 with random number based on step 4
    if stage2_length > max_limit {
        panic!("Max limit reached");
    }

    let mut stage2 = vec![0u8; stage2_length + 1 + 64];
    crate::salsa20::xor_key_stream(&mut stage2[1..stage2_length + 1], &vec![0u8; stage2_length], &key); // Step 6: expand data using Salsa20 with size of step 5
    let mut stage2_result = [0u8; 1024 * 1024 + STAGE1_LENGTH + 1];
    sort_indices(stage2_length + 1, &stage2, &mut stage2_result); // Step 7: Calculate BWT of data from step 6
    let key = sha3(&stage2_result[..stage2_length + 1]); // Step 8: calculate SHA3 of BWT data from step 7
    key.into()
}

fn sha3(input: &[u8]) -> [u8; 32] {
    let mut output: [u8; 32] = [0; 32];
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    
    output.copy_from_slice(hasher.finalize().as_slice());
    output
}

fn smaller(input: &[u8], a: &u64, b: &u64) -> bool {
    let value_a = a >> 21;
    let value_b = b >> 21;

    if value_a < value_b {
        return true;
    }

    if value_a > value_b {
        return false;
    }

    BigEndian::read_u64(&input[(a % (1 << 21)) as usize + 5..])
        < BigEndian::read_u64(&input[(b % (1 << 21)) as usize + 5..])
}

fn sort_indices(n: usize, input_extra: &[u8], output: &mut [u8]) {
    let mut indices = vec![0u64; MAX_LENGTH];
    let mut tmp_indices = vec![0u64; MAX_LENGTH];
    let mut counters = [[0u32; COUNTING_SORT_SIZE as usize]; 2];
    let input = &input_extra[1..];
    let loop3 = n / 3 * 3;
    let mut i = 0;
    while i < loop3 {
        let k0 = BigEndian::read_u64(&input[i..]);
        counters[0][((k0 >> (64 - COUNTING_SORT_BITS * 2)) & (COUNTING_SORT_SIZE - 1)) as usize] += 1;
        counters[1][(k0 >> (64 - COUNTING_SORT_BITS)) as usize] += 1;
        let k1 = k0 << 8;
        counters[0][((k1 >> (64 - COUNTING_SORT_BITS * 2)) & (COUNTING_SORT_SIZE - 1)) as usize] += 1;
        counters[1][(k1 >> (64 - COUNTING_SORT_BITS)) as usize] += 1;
        let k2 = k0 << 16;
        counters[0][((k2 >> (64 - COUNTING_SORT_BITS * 2)) & (COUNTING_SORT_SIZE - 1)) as usize] += 1;
        counters[1][(k2 >> (64 - COUNTING_SORT_BITS)) as usize] += 1;

        i += 3;
    }

    if n % 3 != 0 {
        for i in loop3..n {
            let k = BigEndian::read_u64(&input[i..]);
            counters[0][((k >> (64 - COUNTING_SORT_BITS * 2)) & (COUNTING_SORT_SIZE - 1)) as usize] += 1;
            counters[1][(k >> (64 - COUNTING_SORT_BITS)) as usize] += 1;
        }
    }

    let mut prev: [u32; 2] = [counters[0][0], counters[1][0]];
    counters[0][0] = prev[0] - 1;
    counters[1][0] = prev[1] - 1;
    let mut cur: [u32; 2] = [0, 0];
    for i in 1..COUNTING_SORT_SIZE {
        cur[0] = counters[0][i as usize] + prev[0];
        cur[1] = counters[1][i as usize] + prev[1];
        counters[0][i as usize] = cur[0] - 1;
        counters[1][i as usize] = cur[1] - 1;
        prev[0] = cur[0];
        prev[1] = cur[1];
    }

    for i in 0..n {
        let k = BigEndian::read_u64(&input[i..]);
        let idx = ((k >> (64 - COUNTING_SORT_BITS * 2)) & (COUNTING_SORT_SIZE - 1)) as usize;
        let tmp = counters[0][idx];
        counters[0][idx] = u32::wrapping_sub(counters[0][idx], 1);

        tmp_indices[tmp as usize] = (k & 0xFFFFFFFFFFE00000) | i as u64;
    }

    for i in 0..n {
        let data = tmp_indices[i];
        let tmp = counters[1][(data >> (64 - COUNTING_SORT_BITS)) as usize];
        counters[1][(data >> (64 - COUNTING_SORT_BITS)) as usize] = u32::wrapping_sub(counters[1][(data >> (64 - COUNTING_SORT_BITS)) as usize], 1);
        indices[tmp as usize] = data;
    }

    let mut prev_t = indices[0];
    for i in 1..n {
        let mut t = indices[i];
        if smaller(&input, &t, &prev_t) {
            let t2 = prev_t;
            let mut j: isize = (i - 1) as isize;
            loop {
                indices[j as usize + 1] = prev_t;
                j -= 1;
                if j < 0 {
                    break;
                }

                prev_t = indices[j as usize];
                if !smaller(&input, &t, &prev_t) {
                    break;
                }
            }
            indices[isize::wrapping_add(j, 1) as usize] = t;
            t = t2;
        }
        prev_t = t;
    }

    let loop4 = ((n + 1) / 4) * 4;
    i = 0;
    while i < loop4 {
        output[i + 0] = input_extra[(indices[i + 0] & ((1 << 21) - 1)) as usize];
        output[i + 1] = input_extra[(indices[i + 1] & ((1 << 21) - 1)) as usize];
        output[i + 2] = input_extra[(indices[i + 2] & ((1 << 21) - 1)) as usize];
        output[i + 3] = input_extra[(indices[i + 3] & ((1 << 21) - 1)) as usize];
        i += 4;
    }

    for i in loop4..n {
        output[i] = input_extra[(indices[i] & ((1 << 21) - 1)) as usize];
    }

    if n > 3 && input[n - 2] == 0 {
        let backup_byte = output[0];
        output[0] = 0;
        for i in 1..n {
            if output[i] != 0 {
                output[i - 1] = backup_byte;
                break;
            }
        }
    }
}
