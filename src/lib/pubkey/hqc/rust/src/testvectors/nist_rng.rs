//! Test-only NIST AES-256 CTR_DRBG, matching upstream lib/nist-rng/rng.c.
//! Each `read` is one randombytes request, including the post-request update.
use aes::{
    Aes256,
    cipher::{BlockEncrypt, KeyInit},
};
use crate::error::Result;
use crate::hash::Xof;

pub struct NistRng {
    key: [u8; 32],
    v: [u8; 16],
}

impl NistRng {
    pub fn new(seed: &[u8; 48]) -> Self {
        let mut rng = Self {
            key: [0; 32],
            v: [0; 16],
        };
        rng.update(Some(seed));
        rng
    }

    fn block(&mut self) -> [u8; 16] {
        for b in self.v.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        let cipher = Aes256::new((&self.key).into());
        let mut block = self.v.into();
        cipher.encrypt_block(&mut block);
        block.into()
    }

    fn update(&mut self, seed: Option<&[u8; 48]>) {
        let mut tmp = [0u8; 48];
        for chunk in tmp.chunks_exact_mut(16) {
            chunk.copy_from_slice(&self.block());
        }
        if let Some(seed) = seed {
            for (x, y) in tmp.iter_mut().zip(seed) {
                *x ^= y;
            }
        }
        self.key.copy_from_slice(&tmp[..32]);
        self.v.copy_from_slice(&tmp[32..]);
    }
}

impl Xof for NistRng {
    fn squeeze(&mut self, output: &mut [u8]) -> Result<()> {
        for chunk in output.chunks_mut(16) {
            chunk.copy_from_slice(&self.block()[..chunk.len()]);
        }
        self.update(None);
        Ok(())
    }
}
