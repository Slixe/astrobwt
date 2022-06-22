const OFFSET: u64 = 14695981039346656037;
const PRIME: u64 = 1099511628211;

pub fn hash_bytes_64(mut data: &[u8]) -> u64 {
    let mut h = OFFSET;
    while data.len() >= 8 {
        let _ = data[0..7];
		h = (h ^ (data[0] as u64)) * PRIME;
		h = (h ^ (data[1] as u64)) * PRIME;
		h = (h ^ (data[2] as u64)) * PRIME;
		h = (h ^ (data[3] as u64)) * PRIME;
		h = (h ^ (data[4] as u64)) * PRIME;
		h = (h ^ (data[5] as u64)) * PRIME;
		h = (h ^ (data[6] as u64)) * PRIME;
		h = (h ^ (data[7] as u64)) * PRIME;
		data = &data[8..];
	}

	if data.len() >= 4 {
        let _ = data[0..3];
		h = (h ^ (data[0] as u64)) * PRIME;
		h = (h ^ (data[1] as u64)) * PRIME;
		h = (h ^ (data[2] as u64)) * PRIME;
		h = (h ^ (data[3] as u64)) * PRIME;
		data = &data[4..];
	}

	if data.len() >= 2 {
        let _ = data[0..1];
		h = (h ^ (data[0] as u64)) * PRIME;
		h = (h ^ (data[1] as u64)) * PRIME;
		data = &data[2..];
	}

	if data.len() > 0 {
		h = (h ^ (data[0] as u64)) * PRIME;
	}

	return h
}
