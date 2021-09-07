use sha3::{Digest, Sha3_256};
use std::time::Instant;
use std::convert::TryInto;

const STAGE1_LENGTH: usize = 147253;
const COUNTING_SORT_BITS: u64 = 10;
const COUNTING_SORT_SIZE: u64 = 1 << COUNTING_SORT_BITS;
pub const MAX_LENGTH: usize = 1024 * 1024 + STAGE1_LENGTH + 1024;

pub fn compute(input: &[u8], max_limit: usize) -> Vec<u8> {
    let mut key = sha3(&input); // Step 1: calculate SHA3 of input data
    let mut stage1 = [0u8; STAGE1_LENGTH + 64];
    crate::salsa20::xor_key_stream(
        &mut stage1[1..STAGE1_LENGTH + 1],
        &[0u8; STAGE1_LENGTH],
        &key,
    ); // Step 2: expand data using Salsa20
    let mut stage1_result = [0u8; STAGE1_LENGTH + 1];
    sort_indices(STAGE1_LENGTH + 1, &mut stage1, &mut stage1_result); // Step 3: calculate BWT of step 2
    key = sha3(&stage1_result); // Step 4: calculate SHA3 of BWT data

    let stage2_length = STAGE1_LENGTH + (u32::from_le_bytes(key[0..4].try_into().unwrap()) & 0xfffff) as usize; // Step 5: calculate size of stage2 with random number based on step 4
    if stage2_length > max_limit {
        panic!("Max limit reached");
    }

    let mut stage2 = vec![0u8; stage2_length + 1 + 64];
    crate::salsa20::xor_key_stream(
        &mut stage2[1..stage2_length + 1],
        &vec![0u8; stage2_length],
        &key,
    ); // Step 6: expand data using Salsa20 with size of step 5
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

    u64::from_be_bytes(input[1+(a % (C+1)) as usize + 5..1+((a % (C+1)) as usize + 5 + 8)].try_into().unwrap()) < u64::from_be_bytes(input[1+(b % (C+1)) as usize + 5..1+(b % (C+1)) as usize + 5 + 8].try_into().unwrap())
}

const A: u64 = 64 - COUNTING_SORT_BITS;
const B: u64 = 64 - COUNTING_SORT_BITS * 2;
const C: u64 = (1 << 21) - 1;

fn sort_indices(n: usize, input_extra: &[u8], output: &mut [u8]) {
    let mut indices = vec![0u64; n + 1];
    let mut tmp_indices = vec![0u64; n + 1];
    let mut counters = [[0u32; COUNTING_SORT_SIZE as usize]; 2];
    let loop3 = n / 3 * 3;
    for i in (0..loop3).step_by(3) {
        let k0 = u64::from_be_bytes(input_extra[1+i..1+i+8].try_into().unwrap());
        counters[0][((k0 >> B) & (COUNTING_SORT_SIZE - 1)) as usize] += 1;
        counters[1][(k0 >> A) as usize] += 1;
        let k1 = k0 << 8;
        counters[0][((k1 >> B) & (COUNTING_SORT_SIZE - 1)) as usize] += 1;
        counters[1][(k1 >> A) as usize] += 1;
        let k2 = k0 << 16;
        counters[0][((k2 >> B) & (COUNTING_SORT_SIZE - 1)) as usize] += 1;
        counters[1][(k2 >> A) as usize] += 1;
    }

    if n % 3 != 0 {
        for i in loop3..n {
            let k = u64::from_be_bytes(input_extra[1+i..1+i+8].try_into().unwrap());
            counters[0][((k >> B) & (COUNTING_SORT_SIZE - 1)) as usize] += 1;
            counters[1][(k >> A) as usize] += 1;
        }
    }

    let mut prev: [u32; 2] = [counters[0][0], counters[1][0]];
    counters[0][0] = prev[0] - 1;
    counters[1][0] = prev[1] - 1;
    let mut cur: [u32; 2] = [0, 0];
    for i in 1..COUNTING_SORT_SIZE as usize {
        cur[0] = counters[0][i] + prev[0];
        cur[1] = counters[1][i] + prev[1];
        counters[0][i] = cur[0] - 1;
        counters[1][i] = cur[1] - 1;
        prev[0] = cur[0];
        prev[1] = cur[1];
    }

    for i in (0..n).rev() {
        let k = u64::from_be_bytes(input_extra[1+i..1+i+8].try_into().unwrap());
        let idx = ((k >> B) & (COUNTING_SORT_SIZE - 1)) as usize;
        let tmp = counters[0][idx];
        counters[0][idx] = u32::wrapping_sub(counters[0][idx], 1);

        tmp_indices[tmp as usize] = (k & 0xFFFFFFFFFFE00000) | i as u64;
    }

    for i in (0..n).rev() {
        let data = tmp_indices[i];
        let tmp = counters[1][(data >> A) as usize];
        counters[1][(data >> A) as usize] = u32::wrapping_sub(counters[1][(data >> A) as usize], 1);
        indices[tmp as usize] = data;
    }

    let mut prev_t = indices[0];
    for i in 1..n {
        let mut t = indices[i];
        if smaller(&input_extra, &t, &prev_t) {
            let t2 = prev_t;
            let mut j: isize = (i - 1) as isize;
            loop {
                indices[j as usize + 1] = prev_t;
                j -= 1;
                if j < 0 {
                    break;
                }

                prev_t = indices[j as usize];
                if !smaller(&input_extra, &t, &prev_t) {
                    break;
                }
            }
            indices[isize::wrapping_add(j, 1) as usize] = t;
            t = t2;
        }
        prev_t = t;
    }

    let loop4 = ((n + 1) / 4) * 4;
    for i in (0..loop4).step_by(4) {
        output[i + 0] = input_extra[(indices[i + 0] & C) as usize];
        output[i + 1] = input_extra[(indices[i + 1] & C) as usize];
        output[i + 2] = input_extra[(indices[i + 2] & C) as usize];
        output[i + 3] = input_extra[(indices[i + 3] & C) as usize];
    }

    for i in loop4..n {
        output[i] = input_extra[(indices[i] & C) as usize];
    }

    if n > 3 && input_extra[1 + n - 2] == 0 {
        let backup_byte = output[0];
        output[0] = 0;
        for i in 1..n {
            if output[i] != 0 {
                output[i - 1] = backup_byte;
                break;
            }
        }
    }

    //println!("sort indices: {}ms", start.elapsed().as_millis());
}
