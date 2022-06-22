pub struct Cipher {
    s: [u32; 256],
    i: u8,
    j: u8
}

impl Cipher {
    pub fn new(key: &[u8]) -> Self {
        let k = key.len();
        if k < 1 || k > 256 {
            panic!("invalid key");
        }
        let mut c = Self {
            s: [0u32; 256],
            i: 0,
            j: 0
        };

        let mut j: u8 = 0;
        for i in 0..256 {
            j += (c.s[i] as u8) + key[i % k];
            (c.s[i], c.s[j as usize]) = (c.s[j as usize], c.s[i]);
        }
        c
    }

    pub fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) {
        let len = src.len();
        if len == 0 {
            return
        }
        let _ = src[0..len];
        let _ = dst[0..len];

        for (k, v) in src.iter().enumerate() {
            self.i += 1;
            let x = self.s[self.i as usize];
            self.j += x as u8;
            let y = self.s[self.j as usize];
            (self.s[self.i as usize], self.s[self.j as usize]) = (y, x);
            dst[k] = v ^ (self.s[((x+y) as u8) as usize] as u8);
        }
    }
}