/*
* GOST 34.11
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/gost_3411.h>

#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

namespace Botan {

/**
* GOST 34.11 Constructor
*/
GOST_34_11::GOST_34_11() : m_cipher(GOST_28147_89_Params("R3411_CryptoPro")), m_sum(32), m_hash(32) {
   m_count = 0;
}

void GOST_34_11::clear() {
   m_cipher.clear();
   zeroise(m_sum);
   zeroise(m_hash);
   m_count = 0;
   m_buffer.clear();
}

std::unique_ptr<HashFunction> GOST_34_11::copy_state() const {
   return std::make_unique<GOST_34_11>(*this);
}

/**
* Hash additional inputs
*/
void GOST_34_11::add_data(std::span<const uint8_t> input) {
   BufferSlicer in(input);

   while(!in.empty()) {
      if(const auto one_block = m_buffer.handle_unaligned_data(in)) {
         compress_n(one_block->data(), 1);
      }

      if(m_buffer.in_alignment()) {
         const auto [aligned_data, full_blocks] = m_buffer.aligned_data_to_process(in);
         if(full_blocks > 0) {
            compress_n(aligned_data.data(), full_blocks);
         }
      }
   }

   m_count += input.size();
}

/**
* The GOST 34.11 compression function
*/
void GOST_34_11::compress_n(const uint8_t input[], size_t blocks) {
   for(size_t i = 0; i != blocks; ++i) {
      for(uint16_t j = 0, carry = 0; j != 32; ++j) {
         uint16_t s = m_sum[j] + input[32 * i + j] + carry;
         carry = get_byte<0>(s);
         m_sum[j] = get_byte<1>(s);
      }

      uint8_t S[32] = {0};

      uint64_t U[4], V[4];
      load_be(U, m_hash.data(), 4);
      load_be(V, input + 32 * i, 4);

      for(size_t j = 0; j != 4; ++j) {
         uint8_t key[32] = {0};

         // P transformation
         for(size_t k = 0; k != 4; ++k) {
            const uint64_t UVk = U[k] ^ V[k];
            for(size_t l = 0; l != 8; ++l) {
               key[4 * l + k] = get_byte_var(l, UVk);
            }
         }

         m_cipher.set_key(key, 32);
         m_cipher.encrypt(&m_hash[8 * j], S + 8 * j);

         if(j == 3) {
            break;
         }

         // A(x)
         uint64_t A_U = U[0];
         U[0] = U[1];
         U[1] = U[2];
         U[2] = U[3];
         U[3] = U[0] ^ A_U;

         if(j == 1)  // C_3
         {
            U[0] ^= 0x00FF00FF00FF00FF;
            U[1] ^= 0xFF00FF00FF00FF00;
            U[2] ^= 0x00FFFF00FF0000FF;
            U[3] ^= 0xFF000000FFFF00FF;
         }

         // A(A(x))
         uint64_t AA_V_1 = V[0] ^ V[1];
         uint64_t AA_V_2 = V[1] ^ V[2];
         V[0] = V[2];
         V[1] = V[3];
         V[2] = AA_V_1;
         V[3] = AA_V_2;
      }

      uint8_t S2[32] = {0};

      // 12 rounds of psi
      S2[0] = S[24];
      S2[1] = S[25];
      S2[2] = S[26];
      S2[3] = S[27];
      S2[4] = S[28];
      S2[5] = S[29];
      S2[6] = S[30];
      S2[7] = S[31];
      S2[8] = S[0] ^ S[2] ^ S[4] ^ S[6] ^ S[24] ^ S[30];
      S2[9] = S[1] ^ S[3] ^ S[5] ^ S[7] ^ S[25] ^ S[31];
      S2[10] = S[0] ^ S[8] ^ S[24] ^ S[26] ^ S[30];
      S2[11] = S[1] ^ S[9] ^ S[25] ^ S[27] ^ S[31];
      S2[12] = S[0] ^ S[4] ^ S[6] ^ S[10] ^ S[24] ^ S[26] ^ S[28] ^ S[30];
      S2[13] = S[1] ^ S[5] ^ S[7] ^ S[11] ^ S[25] ^ S[27] ^ S[29] ^ S[31];
      S2[14] = S[0] ^ S[4] ^ S[8] ^ S[12] ^ S[24] ^ S[26] ^ S[28];
      S2[15] = S[1] ^ S[5] ^ S[9] ^ S[13] ^ S[25] ^ S[27] ^ S[29];
      S2[16] = S[2] ^ S[6] ^ S[10] ^ S[14] ^ S[26] ^ S[28] ^ S[30];
      S2[17] = S[3] ^ S[7] ^ S[11] ^ S[15] ^ S[27] ^ S[29] ^ S[31];
      S2[18] = S[0] ^ S[2] ^ S[6] ^ S[8] ^ S[12] ^ S[16] ^ S[24] ^ S[28];
      S2[19] = S[1] ^ S[3] ^ S[7] ^ S[9] ^ S[13] ^ S[17] ^ S[25] ^ S[29];
      S2[20] = S[2] ^ S[4] ^ S[8] ^ S[10] ^ S[14] ^ S[18] ^ S[26] ^ S[30];
      S2[21] = S[3] ^ S[5] ^ S[9] ^ S[11] ^ S[15] ^ S[19] ^ S[27] ^ S[31];
      S2[22] = S[0] ^ S[2] ^ S[10] ^ S[12] ^ S[16] ^ S[20] ^ S[24] ^ S[28] ^ S[30];
      S2[23] = S[1] ^ S[3] ^ S[11] ^ S[13] ^ S[17] ^ S[21] ^ S[25] ^ S[29] ^ S[31];
      S2[24] = S[0] ^ S[6] ^ S[12] ^ S[14] ^ S[18] ^ S[22] ^ S[24] ^ S[26];
      S2[25] = S[1] ^ S[7] ^ S[13] ^ S[15] ^ S[19] ^ S[23] ^ S[25] ^ S[27];
      S2[26] = S[2] ^ S[8] ^ S[14] ^ S[16] ^ S[20] ^ S[24] ^ S[26] ^ S[28];
      S2[27] = S[3] ^ S[9] ^ S[15] ^ S[17] ^ S[21] ^ S[25] ^ S[27] ^ S[29];
      S2[28] = S[4] ^ S[10] ^ S[16] ^ S[18] ^ S[22] ^ S[26] ^ S[28] ^ S[30];
      S2[29] = S[5] ^ S[11] ^ S[17] ^ S[19] ^ S[23] ^ S[27] ^ S[29] ^ S[31];
      S2[30] = S[0] ^ S[2] ^ S[4] ^ S[12] ^ S[18] ^ S[20] ^ S[28];
      S2[31] = S[1] ^ S[3] ^ S[5] ^ S[13] ^ S[19] ^ S[21] ^ S[29];

      xor_buf(S, S2, input + 32 * i, 32);

      S2[0] = S[0] ^ S[2] ^ S[4] ^ S[6] ^ S[24] ^ S[30];
      S2[1] = S[1] ^ S[3] ^ S[5] ^ S[7] ^ S[25] ^ S[31];

      copy_mem(S, S + 2, 30);
      S[30] = S2[0];
      S[31] = S2[1];

      xor_buf(S, m_hash.data(), 32);

      // 61 rounds of psi
      S2[0] = S[2] ^ S[6] ^ S[14] ^ S[20] ^ S[22] ^ S[26] ^ S[28] ^ S[30];
      S2[1] = S[3] ^ S[7] ^ S[15] ^ S[21] ^ S[23] ^ S[27] ^ S[29] ^ S[31];
      S2[2] = S[0] ^ S[2] ^ S[6] ^ S[8] ^ S[16] ^ S[22] ^ S[28];
      S2[3] = S[1] ^ S[3] ^ S[7] ^ S[9] ^ S[17] ^ S[23] ^ S[29];
      S2[4] = S[2] ^ S[4] ^ S[8] ^ S[10] ^ S[18] ^ S[24] ^ S[30];
      S2[5] = S[3] ^ S[5] ^ S[9] ^ S[11] ^ S[19] ^ S[25] ^ S[31];
      S2[6] = S[0] ^ S[2] ^ S[10] ^ S[12] ^ S[20] ^ S[24] ^ S[26] ^ S[30];
      S2[7] = S[1] ^ S[3] ^ S[11] ^ S[13] ^ S[21] ^ S[25] ^ S[27] ^ S[31];
      S2[8] = S[0] ^ S[6] ^ S[12] ^ S[14] ^ S[22] ^ S[24] ^ S[26] ^ S[28] ^ S[30];
      S2[9] = S[1] ^ S[7] ^ S[13] ^ S[15] ^ S[23] ^ S[25] ^ S[27] ^ S[29] ^ S[31];
      S2[10] = S[0] ^ S[4] ^ S[6] ^ S[8] ^ S[14] ^ S[16] ^ S[26] ^ S[28];
      S2[11] = S[1] ^ S[5] ^ S[7] ^ S[9] ^ S[15] ^ S[17] ^ S[27] ^ S[29];
      S2[12] = S[2] ^ S[6] ^ S[8] ^ S[10] ^ S[16] ^ S[18] ^ S[28] ^ S[30];
      S2[13] = S[3] ^ S[7] ^ S[9] ^ S[11] ^ S[17] ^ S[19] ^ S[29] ^ S[31];
      S2[14] = S[0] ^ S[2] ^ S[6] ^ S[8] ^ S[10] ^ S[12] ^ S[18] ^ S[20] ^ S[24];
      S2[15] = S[1] ^ S[3] ^ S[7] ^ S[9] ^ S[11] ^ S[13] ^ S[19] ^ S[21] ^ S[25];
      S2[16] = S[2] ^ S[4] ^ S[8] ^ S[10] ^ S[12] ^ S[14] ^ S[20] ^ S[22] ^ S[26];
      S2[17] = S[3] ^ S[5] ^ S[9] ^ S[11] ^ S[13] ^ S[15] ^ S[21] ^ S[23] ^ S[27];
      S2[18] = S[4] ^ S[6] ^ S[10] ^ S[12] ^ S[14] ^ S[16] ^ S[22] ^ S[24] ^ S[28];
      S2[19] = S[5] ^ S[7] ^ S[11] ^ S[13] ^ S[15] ^ S[17] ^ S[23] ^ S[25] ^ S[29];
      S2[20] = S[6] ^ S[8] ^ S[12] ^ S[14] ^ S[16] ^ S[18] ^ S[24] ^ S[26] ^ S[30];
      S2[21] = S[7] ^ S[9] ^ S[13] ^ S[15] ^ S[17] ^ S[19] ^ S[25] ^ S[27] ^ S[31];
      S2[22] = S[0] ^ S[2] ^ S[4] ^ S[6] ^ S[8] ^ S[10] ^ S[14] ^ S[16] ^ S[18] ^ S[20] ^ S[24] ^ S[26] ^ S[28] ^ S[30];
      S2[23] = S[1] ^ S[3] ^ S[5] ^ S[7] ^ S[9] ^ S[11] ^ S[15] ^ S[17] ^ S[19] ^ S[21] ^ S[25] ^ S[27] ^ S[29] ^ S[31];
      S2[24] = S[0] ^ S[8] ^ S[10] ^ S[12] ^ S[16] ^ S[18] ^ S[20] ^ S[22] ^ S[24] ^ S[26] ^ S[28];
      S2[25] = S[1] ^ S[9] ^ S[11] ^ S[13] ^ S[17] ^ S[19] ^ S[21] ^ S[23] ^ S[25] ^ S[27] ^ S[29];
      S2[26] = S[2] ^ S[10] ^ S[12] ^ S[14] ^ S[18] ^ S[20] ^ S[22] ^ S[24] ^ S[26] ^ S[28] ^ S[30];
      S2[27] = S[3] ^ S[11] ^ S[13] ^ S[15] ^ S[19] ^ S[21] ^ S[23] ^ S[25] ^ S[27] ^ S[29] ^ S[31];
      S2[28] = S[0] ^ S[2] ^ S[6] ^ S[12] ^ S[14] ^ S[16] ^ S[20] ^ S[22] ^ S[26] ^ S[28];
      S2[29] = S[1] ^ S[3] ^ S[7] ^ S[13] ^ S[15] ^ S[17] ^ S[21] ^ S[23] ^ S[27] ^ S[29];
      S2[30] = S[2] ^ S[4] ^ S[8] ^ S[14] ^ S[16] ^ S[18] ^ S[22] ^ S[24] ^ S[28] ^ S[30];
      S2[31] = S[3] ^ S[5] ^ S[9] ^ S[15] ^ S[17] ^ S[19] ^ S[23] ^ S[25] ^ S[29] ^ S[31];

      copy_mem(m_hash.data(), S2, 32);
   }
}

/**
* Produce the final GOST 34.11 output
*/
void GOST_34_11::final_result(std::span<uint8_t> out) {
   if(!m_buffer.in_alignment()) {
      m_buffer.fill_up_with_zeros();
      compress_n(m_buffer.consume().data(), 1);
   }

   secure_vector<uint8_t> length_buf(32);
   const uint64_t bit_count = m_count * 8;
   store_le(bit_count, length_buf.data());

   secure_vector<uint8_t> sum_buf = m_sum;

   compress_n(length_buf.data(), 1);
   compress_n(sum_buf.data(), 1);

   copy_mem(out.data(), m_hash.data(), 32);

   clear();
}

}  // namespace Botan
