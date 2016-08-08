use std::num::Wrapping;

fn rot_r(val: u32, rot: u32) -> u32 {
    assert!(rot < 32);
    (val >> rot) | (val << (32 - rot))
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn b_sigma_0(x: u32) -> u32 {
    rot_r(x, 2) ^ rot_r(x, 13) ^ rot_r(x, 22)
}

fn b_sigma_1(x: u32) -> u32 {
    rot_r(x, 6) ^ rot_r(x, 11) ^ rot_r(x, 25)
}

fn l_sigma_0(x: u32) -> u32 {
    rot_r(x, 7) ^ rot_r(x, 18) ^ (x >> 3)
}

fn l_sigma_1(x: u32) -> u32 {
    rot_r(x, 17) ^ rot_r(x, 19) ^ (x >> 10)
}

// Intial hash state
const INITIAL_HASH_STATE: [u32; 8] = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const BLOCK_SIZE_BYTES: usize = 64;

pub struct Sha256Digestion {
    // Current state of the hash
    hash_state: [u32; 8],
    // This is the block we will read the inputs into.
    // To be later converted into u32s for actual sha operations
    reading_block: Vec<u8>,
    // Number of bits in the message
    bit_count: u64,
}

impl Sha256Digestion {
    pub fn new() -> Sha256Digestion {
        Sha256Digestion {
            hash_state: INITIAL_HASH_STATE,
            reading_block: Vec::with_capacity(BLOCK_SIZE_BYTES),
            bit_count: 0,
        }
    }

    fn update_hash_state(&mut self) -> () {
        // Convert u8s into u32s
        let mut message_block: Vec<u32> = Vec::with_capacity(16);
        for chunk in self.reading_block.chunks(4) {
            assert!(chunk.len() == 4);
            message_block.push(
                (chunk[0] as u32) << 24 |
                (chunk[1] as u32) << 16 |
                (chunk[2] as u32) << 8 |
                (chunk[3] as u32)
            );
        }

        let mut sched: [u32; 64] = [0; 64];
        let mut a: Wrapping<u32> = Wrapping(self.hash_state[0]);
        let mut b: Wrapping<u32> = Wrapping(self.hash_state[1]);
        let mut c: Wrapping<u32> = Wrapping(self.hash_state[2]);
        let mut d: Wrapping<u32> = Wrapping(self.hash_state[3]);
        let mut e: Wrapping<u32> = Wrapping(self.hash_state[4]);
        let mut f: Wrapping<u32> = Wrapping(self.hash_state[5]);
        let mut g: Wrapping<u32> = Wrapping(self.hash_state[6]);
        let mut h: Wrapping<u32> = Wrapping(self.hash_state[7]);

        for (i, m) in message_block.iter().enumerate() {
            sched[i] = *m;
        }
        for t in 16..64 {
            sched[t] = (Wrapping(l_sigma_1(sched[t-2])) + Wrapping(sched[t-7]) + Wrapping(l_sigma_0(sched[t-15])) + Wrapping(sched[t-16])).0;
        }

        // TODO: Use zip(K, sched)
        for t in 0..64 {
            let t1 = h + Wrapping(b_sigma_1(e.0)) + Wrapping(ch(e.0, f.0, g.0)) + Wrapping(K[t]) + Wrapping(sched[t]);
            let t2 = Wrapping(b_sigma_0(a.0)) + Wrapping(maj(a.0, b.0, c.0));
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        self.hash_state[0] = (Wrapping(self.hash_state[0]) + a).0;
        self.hash_state[1] = (Wrapping(self.hash_state[1]) + b).0;
        self.hash_state[2] = (Wrapping(self.hash_state[2]) + c).0;
        self.hash_state[3] = (Wrapping(self.hash_state[3]) + d).0;
        self.hash_state[4] = (Wrapping(self.hash_state[4]) + e).0;
        self.hash_state[5] = (Wrapping(self.hash_state[5]) + f).0;
        self.hash_state[6] = (Wrapping(self.hash_state[6]) + g).0;
        self.hash_state[7] = (Wrapping(self.hash_state[7]) + h).0;
    }

    /// Produce the final hash value
    pub fn digest(mut self) -> [u8; 32] {
        // We know this fits (or add_byte would have flushed)
        self.reading_block.push(0x80);

        // Not enough space to add 64 bit length on the end
        if self.reading_block.len() >= BLOCK_SIZE_BYTES - 8 {
            // Fill up with things
            while self.reading_block.len() < BLOCK_SIZE_BYTES {
                self.reading_block.push(0);
            }
            self.update_hash_state();
            self.reading_block.clear();
        }

        // Pad with zeros until we should add the length
        while self.reading_block.len() < BLOCK_SIZE_BYTES - 8 {
            self.reading_block.push(0);
        }
        // TODO: This might also be the wrong way on
        // Now push on the length
        for i in 0..8 {
            self.reading_block.push((self.bit_count >> ((7 - i) * 8)) as u8);
        }
        self.update_hash_state();
        self.reading_block.clear();

        let mut hash_output: [u8; 32] = [0; 32];
        for (i, h) in self.hash_state.iter().enumerate() {
            hash_output[(i * 4)] = (h >> 24) as u8;
            hash_output[(i * 4) + 1] = (h >> 16) as u8;
            hash_output[(i * 4) + 2] = (h >> 8) as u8;
            hash_output[(i * 4) + 3] = *h as u8;
        }

        hash_output
    }

    /// Add a single byte to the digest
    pub fn add_byte(&mut self, byte: u8) -> () {
        self.reading_block.push(byte);
        self.bit_count += 8;
        if self.reading_block.len() == BLOCK_SIZE_BYTES {
            // We have a full block: update hash state
            self.update_hash_state();
            self.reading_block.clear();
        }
    }

    // Add Reader
    // Add Vector, Array, Slice, etc
    // Any more?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_message() {
        // From NIST examples
        let expected_hash: [u8; 32] = [
            0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
            0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
            0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
            0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD,
        ];
        let mut s = Sha256Digestion::new();
        // 'abc'
        s.add_byte(97);
        s.add_byte(98);
        s.add_byte(99);
        let h = s.digest();
        assert_eq!(h, expected_hash);
    }
}
