/*
* AES using hardware AES instructions
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/aes.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/simd_4x32.h>
#include <botan/internal/simd_hwaes.h>
#include <utility>

namespace Botan {

namespace {

template <bool ENC>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES SIMD_4x32 hw_aes_round(SIMD_4x32 B, SIMD_4x32 K) {
   if constexpr(ENC) {
      return hw_aes_enc_round(B, K);
   } else {
      return hw_aes_dec_round(B, K);
   }
}

template <bool ENC>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES SIMD_4x32 hw_aes_last_round(SIMD_4x32 B, SIMD_4x32 K) {
   if constexpr(ENC) {
      return hw_aes_enc_last_round(B, K);
   } else {
      return hw_aes_dec_last_round(B, K);
   }
}

template <bool ENC, typename... Bs>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES void hw_aes_round_all(SIMD_4x32 K, Bs&... B) {
   ((B = hw_aes_round<ENC>(B, K)), ...);
}

// The round keys are indexed with constants so that GCC keeps them in registers
template <size_t R, bool ENC, size_t... Is, typename... Bs>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES void hw_aes_inner_rounds(const SIMD_4x32 (&K)[R + 1],
                                                               std::index_sequence<Is...> /*rounds*/,
                                                               Bs&... B) {
   constexpr size_t S = HwAesKeyFirst ? 0 : 1;
   (hw_aes_round_all<ENC>(K[Is + S], B...), ...);
}

/*
* Run the full cipher over any number of blocks in parallel. Where the ISA adds
* the round key before SubBytes the whitening key goes into the first round
* instruction, otherwise the last round key goes into the final one.
*/
template <size_t R, bool ENC, typename... Bs>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES void hw_aes_blocks(const SIMD_4x32 (&K)[R + 1], Bs&... B) {
   constexpr size_t S = HwAesKeyFirst ? 0 : 1;

   if constexpr(!HwAesKeyFirst) {
      ((B ^= K[0]), ...);
   }

   hw_aes_inner_rounds<R, ENC>(K, std::make_index_sequence<R - 1>{}, B...);

   ((B = hw_aes_last_round<ENC>(B, K[R - 1 + S])), ...);

   if constexpr(HwAesKeyFirst) {
      ((B ^= K[R]), ...);
   }
}

template <size_t R, size_t... Is>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES void hw_aes_load_keys(SIMD_4x32 (&K)[R + 1],
                                                            const uint32_t keys[],
                                                            std::index_sequence<Is...> /*keys*/) {
   ((K[Is] = hw_aes_load_block(reinterpret_cast<const uint8_t*>(&keys[4 * Is]))), ...);
}

template <size_t R, bool ENC>
BOTAN_FN_ISA_HWAES void hw_aes_process(const uint8_t in[], uint8_t out[], size_t blocks, const uint32_t keys[]) {
   SIMD_4x32 K[R + 1];
   hw_aes_load_keys<R>(K, keys, std::make_index_sequence<R + 1>{});

   while(blocks >= 4) {
      SIMD_4x32 B0 = hw_aes_load_block(in);
      SIMD_4x32 B1 = hw_aes_load_block(in + 16);
      SIMD_4x32 B2 = hw_aes_load_block(in + 32);
      SIMD_4x32 B3 = hw_aes_load_block(in + 48);

      hw_aes_blocks<R, ENC>(K, B0, B1, B2, B3);

      hw_aes_store_block(B0, out);
      hw_aes_store_block(B1, out + 16);
      hw_aes_store_block(B2, out + 32);
      hw_aes_store_block(B3, out + 48);

      in += 4 * 16;
      out += 4 * 16;
      blocks -= 4;
   }

   for(size_t i = 0; i != blocks; ++i) {
      SIMD_4x32 B = hw_aes_load_block(in + 16 * i);
      hw_aes_blocks<R, ENC>(K, B);
      hw_aes_store_block(B, out + 16 * i);
   }
}

/*
* Each word of a round key is the xor of the previous word and the word four
* positions back. So given the previous round key and t = SubWord(RotWord(w))
* ^ Rcon broadcast to every word, the new round key is the running xor over
* the words of prev, with t folded into each.
*/
BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES SIMD_4x32 next_round_key(SIMD_4x32 prev, SIMD_4x32 t) {
   prev ^= prev.shift_elems_left<1>();
   prev ^= prev.shift_elems_left<2>();
   return prev ^ t;
}

// SubWord(RotWord(w3)) ^ rcon broadcast to all four words
BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES SIMD_4x32 sub_rot_w3(SIMD_4x32 k, SIMD_4x32 rcon) {
   return hw_aes_sbox_splat(SIMD_4x32::byte_shuffle(k, SIMD_4x32::splat(0x0C0F0E0D)), rcon);
}

// SubWord(w3) broadcast to all four words
BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES SIMD_4x32 sub_w3(SIMD_4x32 k) {
   return hw_aes_sbox_splat(SIMD_4x32::byte_shuffle(k, SIMD_4x32::splat(0x0F0E0D0C)), SIMD_4x32());
}

// SubWord(RotWord(w1)) ^ rcon broadcast to all four words
BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES SIMD_4x32 sub_rot_w1(SIMD_4x32 k, SIMD_4x32 rcon) {
   return hw_aes_sbox_splat(SIMD_4x32::byte_shuffle(k, SIMD_4x32::splat(0x04070605)), rcon);
}

template <uint8_t RC>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES SIMD_4x32 aes_128_round_key(SIMD_4x32 prev, uint32_t out[]) {
   const auto K = next_round_key(prev, sub_rot_w3(prev, SIMD_4x32::splat(RC)));
   K.store_le(out);
   return K;
}

/*
* AES-192 produces six words per step, four in K0 and two in the low half of
* K1. The high half of K1 is garbage, so it is written before the following
* four words, which overwrite it.
*/
template <uint8_t RC>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES void aes_192_round_keys(SIMD_4x32& K0, SIMD_4x32& K1, uint32_t out[]) {
   K0 = next_round_key(K0, sub_rot_w1(K1, SIMD_4x32::splat(RC)));
   K0.store_le(out);
   K1 ^= K1.shift_elems_left<1>();
   K1 ^= SIMD_4x32::byte_shuffle(K0, SIMD_4x32::splat(0x0F0E0D0C));
   K1.store_le(out + 4);
}

// AES-256 alternates between the two key halves; the second uses SubWord alone
template <uint8_t RC>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES void aes_256_round_keys(SIMD_4x32& K0, SIMD_4x32& K1, uint32_t out[]) {
   K0 = next_round_key(K0, sub_rot_w3(K1, SIMD_4x32::splat(RC)));
   K0.store_le(out);
   K1 = next_round_key(K1, sub_w3(K0));
   K1.store_le(out + 4);
}

/*
* The decryption round keys are the encryption round keys in reverse order,
* with the inner ones converted to the form the decryption instructions take
*/
BOTAN_FN_ISA_HWAES void hw_aes_decryption_keys(const secure_vector<uint32_t>& EK, secure_vector<uint32_t>& DK) {
   const size_t rounds = EK.size() / 4 - 1;
   DK.resize(EK.size());

   SIMD_4x32::load_le(&EK[4 * rounds]).store_le(DK.data());
   for(size_t i = 1; i != rounds; ++i) {
      hw_aes_dec_round_key(SIMD_4x32::load_le(&EK[4 * (rounds - i)])).store_le(&DK[4 * i]);
   }
   SIMD_4x32::load_le(EK.data()).store_le(&DK[4 * rounds]);
}

}  // namespace

void BOTAN_FN_ISA_HWAES AES_128::hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   hw_aes_process<10, true>(in, out, blocks, m_EK.data());
}

void BOTAN_FN_ISA_HWAES AES_128::hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   hw_aes_process<10, false>(in, out, blocks, m_DK.data());
}

void BOTAN_FN_ISA_HWAES AES_192::hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   hw_aes_process<12, true>(in, out, blocks, m_EK.data());
}

void BOTAN_FN_ISA_HWAES AES_192::hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   hw_aes_process<12, false>(in, out, blocks, m_DK.data());
}

void BOTAN_FN_ISA_HWAES AES_256::hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   hw_aes_process<14, true>(in, out, blocks, m_EK.data());
}

void BOTAN_FN_ISA_HWAES AES_256::hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   hw_aes_process<14, false>(in, out, blocks, m_DK.data());
}

void BOTAN_FN_ISA_HWAES AES_128::hw_aes_key_schedule(std::span<const uint8_t> key) {
   m_EK.resize(44);

   SIMD_4x32 K = SIMD_4x32::load_le(key.first<16>());
   K.store_le(m_EK.data());
   K = aes_128_round_key<0x01>(K, &m_EK[4]);
   K = aes_128_round_key<0x02>(K, &m_EK[8]);
   K = aes_128_round_key<0x04>(K, &m_EK[12]);
   K = aes_128_round_key<0x08>(K, &m_EK[16]);
   K = aes_128_round_key<0x10>(K, &m_EK[20]);
   K = aes_128_round_key<0x20>(K, &m_EK[24]);
   K = aes_128_round_key<0x40>(K, &m_EK[28]);
   K = aes_128_round_key<0x80>(K, &m_EK[32]);
   K = aes_128_round_key<0x1B>(K, &m_EK[36]);
   aes_128_round_key<0x36>(K, &m_EK[40]);

   hw_aes_decryption_keys(m_EK, m_DK);
}

void BOTAN_FN_ISA_HWAES AES_192::hw_aes_key_schedule(std::span<const uint8_t> key) {
   m_EK.resize(52);

   SIMD_4x32 K0 = SIMD_4x32::load_le(key.first<16>());
   SIMD_4x32 K1 = SIMD_4x32::load_le(key.subspan<8, 16>()).shift_elems_right<2>();
   K0.store_le(m_EK.data());
   K1.store_le(&m_EK[4]);

   aes_192_round_keys<0x01>(K0, K1, &m_EK[6]);
   aes_192_round_keys<0x02>(K0, K1, &m_EK[12]);
   aes_192_round_keys<0x04>(K0, K1, &m_EK[18]);
   aes_192_round_keys<0x08>(K0, K1, &m_EK[24]);
   aes_192_round_keys<0x10>(K0, K1, &m_EK[30]);
   aes_192_round_keys<0x20>(K0, K1, &m_EK[36]);
   aes_192_round_keys<0x40>(K0, K1, &m_EK[42]);

   // The final step produces just four words
   K0 = next_round_key(K0, sub_rot_w1(K1, SIMD_4x32::splat(0x80)));
   K0.store_le(&m_EK[48]);

   hw_aes_decryption_keys(m_EK, m_DK);
}

void BOTAN_FN_ISA_HWAES AES_256::hw_aes_key_schedule(std::span<const uint8_t> key) {
   m_EK.resize(60);

   SIMD_4x32 K0 = SIMD_4x32::load_le(key.first<16>());
   SIMD_4x32 K1 = SIMD_4x32::load_le(key.subspan<16, 16>());
   K0.store_le(m_EK.data());
   K1.store_le(&m_EK[4]);

   aes_256_round_keys<0x01>(K0, K1, &m_EK[8]);
   aes_256_round_keys<0x02>(K0, K1, &m_EK[16]);
   aes_256_round_keys<0x04>(K0, K1, &m_EK[24]);
   aes_256_round_keys<0x08>(K0, K1, &m_EK[32]);
   aes_256_round_keys<0x10>(K0, K1, &m_EK[40]);
   aes_256_round_keys<0x20>(K0, K1, &m_EK[48]);

   // The final step produces just one round key
   K0 = next_round_key(K0, sub_rot_w3(K1, SIMD_4x32::splat(0x40)));
   K0.store_le(&m_EK[56]);

   hw_aes_decryption_keys(m_EK, m_DK);
}

}  // namespace Botan
