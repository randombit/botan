use crate::parameters::*;

/// 128-bit Reed-Muller RM(1,7) codeword.
///
/// Provides word-wise access (4 × 32-bit words).
///
/// `#[repr(C)]` ensures the memory layout matches the original C type:
/// ```c
/// typedef union {
///     uint8_t  u8[16];
///     uint32_t u32[4];
/// } rm_codeword_t;
/// ```
/// Required for correct FFI cross-validation against the C implementation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RmCodeword {
    pub u32: [u32; 4],
}
// pub type RmCodeword = [u32; 4];

impl RmCodeword {
    /// Creates a zero-initialized codeword.
    pub fn zeroed() -> Self {
        Self { u32: [0u32; 4] }
    }

    /// Creates a codeword from 4 32-bit words.
    pub fn new(w0: u32, w1: u32, w2: u32, w3: u32) -> Self {
        Self {
            u32: [w0, w1, w2, w3],
        }
    }
}

/// Compile-time size check - must match C sizeof(rm_codeword_t) = 16 bytes.
const _: () = assert!(
    core::mem::size_of::<RmCodeword>() == 16,
    "RmCodeword must be exactly 16 bytes to match C layout"
);

/// Internal representation of a codeword with each bit expanded
/// to a 16-bit signed value.
///
/// Equivalent to C: `typedef int16_t rm_expanded_cdw[128];`
pub type RmExpandedCdw = [i16; 128];

/// Number of repeated 128-bit codeword blocks.
///
/// Broadcasts the least significant bit of `x` to a 32-bit mask.
///
/// Returns `0xFFFFFFFF` (all ones)  if `x & 1 == 1`
/// Returns `0x00000000` (all zeros) if `x & 1 == 0`
#[inline]
pub const fn bit0mask(x: u32) -> i32 {
    -((x & 1) as i32)
}

/// Encodes a single byte into a single RM(1,7) codeword.
///
/// Encoding matrix (bits numbered big endian):
/// ```text
/// 0   aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa
/// 1   cccccccc cccccccc cccccccc cccccccc
/// 2   f0f0f0f0 f0f0f0f0 f0f0f0f0 f0f0f0f0
/// 3   ff00ff00 ff00ff00 ff00ff00 ff00ff00
/// 4   ffff0000 ffff0000 ffff0000 ffff0000
/// 5   ffffffff 00000000 ffffffff 00000000
/// 6   ffffffff ffffffff 00000000 00000000
/// 7   ffffffff ffffffff ffffffff ffffffff
/// ```
///
/// Constant-time: all operations are branchless bitwise arithmetic.
///
/// # Arguments
/// * `message` - Input byte to encode.
///
/// # Returns
/// An `RmCodeword` containing the RM(1,7) encoded codeword.
pub fn encode(message: i32) -> RmCodeword {
    let mut first_word: i32;

    // Row 7: all-ones mask — broadcast bit 7
    first_word = bit0mask((message >> 7) as u32);

    // XOR with masked generator rows 0..4
    first_word ^= bit0mask((message >> 0) as u32) & 0x55555555_u32 as i32;
    first_word ^= bit0mask((message >> 1) as u32) & 0x33333333_u32 as i32;
    first_word ^= bit0mask((message >> 2) as u32) & 0x0f0f0f0f_u32 as i32;
    first_word ^= bit0mask((message >> 3) as u32) & 0xff00ff00_u32 as i32;
    first_word ^= bit0mask((message >> 4) as u32) & 0xffff0000_u32 as i32;

    let mut word = RmCodeword::zeroed();

    // word[0]: rows 0..4 and row 7
    word.u32[0] = first_word as u32;

    // word[1]: additionally XOR row 5
    first_word ^= bit0mask((message >> 5) as u32);
    word.u32[1] = first_word as u32;

    // word[3]: additionally XOR row 6
    first_word ^= bit0mask((message >> 6) as u32);
    word.u32[3] = first_word as u32;

    // word[2]: undo row 5 (XOR again is its own inverse)
    first_word ^= bit0mask((message >> 5) as u32);
    word.u32[2] = first_word as u32;

    word
}

/// Performs the Hadamard transform of `src`, storing the result in `dst`.
///
/// # Arguments
/// * `src` - Input expanded codeword — overwritten during computation.
/// * `dst` - Output expanded codeword — contains result after transform.
pub fn hadamard(src: &mut RmExpandedCdw, dst: &mut RmExpandedCdw) {
    // Track which buffer is "current input" and "current output"
    // by copying after each pass — slightly less efficient but no unsafe
    let mut bufs: [RmExpandedCdw; 2] = [*src, [0i16; 128]];
    let mut cur = 0usize; // index of current input buffer

    for _pass in 0..7 {
        let next = 1 - cur;
        for i in 0..64usize {
            let a = bufs[cur][2 * i];
            let b = bufs[cur][2 * i + 1];
            bufs[next][i] = a.wrapping_add(b);
            bufs[next][i + 64] = a.wrapping_sub(b);
        }
        cur = next;
    }

    // After 7 passes (odd), result is in bufs[1] = dst
    *dst = bufs[cur];
}

/// Adds multiple codewords into an expanded codeword.
///
/// Accesses memory in order. Uses 0 and 1 (not -1 and +1).
/// The resulting Hadamard transform has:
/// - all values halved
/// - the first entry is 64 too high
///
/// Constant-time: no secret-dependent branches or memory accesses.
///
/// # Arguments
/// * `dest` - Output expanded codeword.
/// * `src`  - The repeated codewords for one symbol. Its length is the
///            parameter set's multiplicity: 3 for HQC-1, 5 for HQC-3 and
///            HQC-5. Taken as a slice rather than a fixed-size array so the
///            multiplicity can be chosen at run time.
pub fn expand_and_sum(dest: &mut RmExpandedCdw, src: &[RmCodeword]) {
    // Initialize dest with the first copy
    for part in 0..4usize {
        for bit in 0..32usize {
            dest[part * 32 + bit] = ((src[0].u32[part] >> (bit ^ 7)) & 1) as i16;
        }
    }

    // Accumulate the remaining copies
    for copy in 1..src.len() {
        for part in 0..4usize {
            for bit in 0..32usize {
                dest[part * 32 + bit] = dest[part * 32 + bit]
                    .wrapping_add(((src[copy].u32[part] >> (bit ^ 7)) & 1) as i16);
            }
        }
    }
}

/// Finds the location of the highest absolute value in the Hadamard transform.
///
/// Final step of the decoder: finds the peak location and sets bit 7
/// if the peak value is positive.
/// If two identical peaks exist, the one with the smallest value
/// in the lowest 7 bits is taken.
///
/// Constant-time with respect to `transform` contents:
/// no secret-dependent branches or memory accesses.
///
/// # Arguments
/// * `transform` - Expanded codeword after Hadamard transform.
///
/// # Returns
/// Peak position with bit 7 set if peak value is positive.
pub fn find_peaks(transform: &RmExpandedCdw) -> i32 {
    let mut peak_abs_value: i32 = 0;
    let mut peak_value: i32 = 0;
    let mut peak_pos: i32 = 0;

    for i in 0..128i32 {
        let t = transform[i as usize] as i32;

        // Constant-time absolute value — no branch on secret t
        // pos_mask = 0xFFFFFFFF if t > 0, else 0x00000000
        let pos_mask: i32 = -((t > 0) as i32);
        let absolute: i32 = (pos_mask & t) | (!pos_mask & t.wrapping_neg());

        // Constant-time conditional update — no branch on secret absolute
        // update_mask = 0xFFFFFFFF if absolute > peak_abs_value, else 0x00000000
        let update_mask: i32 = -((absolute > peak_abs_value) as i32);
        peak_value = (update_mask & t) | (!update_mask & peak_value);
        peak_pos = (update_mask & i) | (!update_mask & peak_pos);
        peak_abs_value = (update_mask & absolute) | (!update_mask & peak_abs_value);
    }

    // Set bit 7 if peak value is positive — constant-time
    // (peak_value > 0) is 0 or 1 — no branch on secret data
    peak_pos |= 128 * ((peak_value > 0) as i32);

    peak_pos
}

/// Encodes the received word using Reed-Muller encoding.
///
/// Each of the `p.vec_n1_size_bytes` message bytes is encoded into
/// `p.multiplicity` repeated 128-bit RM(1,7) codewords.
///
/// # Arguments
/// * `msg` - Input message of `p.vec_n1_size_64` 64-bit words.
///
/// # Returns
/// Encoded codeword array of `p.vec_n1n2_size_64` 64-bit words.
pub fn reed_muller_encode(p: &HqcParameters, msg: &[u64]) -> Vec<u64> {
    assert_eq!(msg.len(), p.vec_n1_size_64);
    let mut output = p.zero_vec_n1n2();

    for (word_idx, &word) in msg.iter().enumerate() {
        for byte_idx in 0..8usize {
            let i = word_idx * 8 + byte_idx;
            if i >= p.vec_n1_size_bytes {
                break;
            }

            // Extract byte in little-endian order
            let byte = (word >> (byte_idx * 8)) as u8;

            // Encode and write p.multiplicity copies directly into output
            let codeword = encode(byte as i32);
            for copy in 0..p.multiplicity {
                let pos = (i * p.multiplicity + copy) * 2;
                for (j, &w32) in codeword.u32.iter().enumerate() {
                    output[pos + j / 2] |= (w32 as u64) << ((j % 2) * 32);
                }
            }
        }
    }

    output
}

pub fn reed_muller_decode(p: &HqcParameters, cdw: &[u64]) -> Vec<u64> {
    assert_eq!(cdw.len(), p.vec_n1n2_size_64);
    let mut output = p.zero_vec_n1();

    for i in 0..p.vec_n1_size_bytes {
        // Extract p.multiplicity codewords starting at i * p.multiplicity
        let pos = i * p.multiplicity * 2;
        let mut src = vec![RmCodeword::zeroed(); p.multiplicity];
        for copy in 0..p.multiplicity {
            let base = pos + copy * 2;
            src[copy].u32[0] = cdw[base] as u32;
            src[copy].u32[1] = (cdw[base] >> 32) as u32;
            src[copy].u32[2] = cdw[base + 1] as u32;
            src[copy].u32[3] = (cdw[base + 1] >> 32) as u32;
        }

        // Expand and sum the codewords
        let mut expanded: RmExpandedCdw = [0i16; 128];
        expand_and_sum(&mut expanded, &src);

        // Apply Hadamard transform
        let mut transform: RmExpandedCdw = [0i16; 128];
        hadamard(&mut expanded, &mut transform);

        // Fix the first entry to get the half Hadamard transform
        transform[0] = transform[0].wrapping_sub((64 * p.multiplicity) as i16);

        // Decode and store the byte into output
        let byte = find_peaks(&transform) as u8;
        let word_idx = i / 8;
        let byte_idx = i % 8;
        output[word_idx] |= (byte as u64) << (byte_idx * 8);
    }

    output
}
