/*
* GCM GHASH
* (C) 2013,2015,2017 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
* (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ghash.h>

#include <botan/exceptn.h>
#include <botan/internal/cpuid.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

namespace Botan {

std::string GHASH::provider() const {
#if defined(BOTAN_HAS_GHASH_CLMUL_CPU)
   if(CPUID::has_carryless_multiply()) {
      return "clmul";
   }
#endif

#if defined(BOTAN_HAS_GHASH_CLMUL_VPERM)
   if(CPUID::has_vperm()) {
      return "vperm";
   }
#endif

   return "base";
}

void GHASH::ghash_multiply(std::span<uint8_t, GCM_BS> x, std::span<const uint8_t> input, size_t blocks) {
   BOTAN_ASSERT_NOMSG(input.size() % GCM_BS == 0);

#if defined(BOTAN_HAS_GHASH_CLMUL_CPU)
   if(CPUID::has_carryless_multiply()) {
      BOTAN_ASSERT_NOMSG(!m_H_pow.empty());
      return ghash_multiply_cpu(x.data(), m_H_pow.data(), input.data(), blocks);
   }
#endif

#if defined(BOTAN_HAS_GHASH_CLMUL_VPERM)
   if(CPUID::has_vperm()) {
      return ghash_multiply_vperm(x.data(), m_HM.data(), input.data(), blocks);
   }
#endif

   auto scope = CT::scoped_poison(x);

   auto X = load_be<std::array<uint64_t, 2>>(x);

   BufferSlicer in(input);
   for(size_t b = 0; b != blocks; ++b) {
      const auto I = load_be<std::array<uint64_t, 2>>(in.take<GCM_BS>());
      X[0] ^= I[0];
      X[1] ^= I[1];

      std::array<uint64_t, 2> Z{};

      for(size_t i = 0; i != 64; ++i) {
         const auto X0MASK = CT::Mask<uint64_t>::expand_top_bit(X[0]);
         const auto X1MASK = CT::Mask<uint64_t>::expand_top_bit(X[1]);

         X[0] <<= 1;
         X[1] <<= 1;

         Z[0] = X0MASK.select(Z[0] ^ m_HM[4 * i], Z[0]);
         Z[1] = X0MASK.select(Z[1] ^ m_HM[4 * i + 1], Z[1]);

         Z[0] = X1MASK.select(Z[0] ^ m_HM[4 * i + 2], Z[0]);
         Z[1] = X1MASK.select(Z[1] ^ m_HM[4 * i + 3], Z[1]);
      }

      X[0] = Z[0];
      X[1] = Z[1];
   }

   store_be(x, X);
}

bool GHASH::has_keying_material() const {
   return !m_HM.empty();
}

void GHASH::key_schedule(std::span<const uint8_t> key) {
   m_H_ad = {0};
   m_ad_len = 0;
   m_text_len = 0;

   BOTAN_ASSERT_NOMSG(key.size() == GCM_BS);
   auto H = load_be<std::array<uint64_t, 2>>(key.first<GCM_BS>());

   const uint64_t R = 0xE100000000000000;

   m_HM.resize(256);

   // precompute the multiples of H
   for(size_t i = 0; i != 2; ++i) {
      for(size_t j = 0; j != 64; ++j) {
         /*
         we interleave H^1, H^65, H^2, H^66, H3, H67, H4, H68
         to make indexing nicer in the multiplication code
         */
         m_HM[4 * j + 2 * i] = H[0];
         m_HM[4 * j + 2 * i + 1] = H[1];

         // GCM's bit ops are reversed so we carry out of the bottom
         const uint64_t carry = CT::Mask<uint64_t>::expand(H[1] & 1).if_set_return(R);
         H[1] = (H[1] >> 1) | (H[0] << 63);
         H[0] = (H[0] >> 1) ^ carry;
      }
   }

#if defined(BOTAN_HAS_GHASH_CLMUL_CPU)
   if(CPUID::has_carryless_multiply()) {
      m_H_pow.resize(8);
      ghash_precompute_cpu(key.data(), m_H_pow.data());
   }
#endif
}

void GHASH::start(std::span<const uint8_t> nonce) {
   BOTAN_ARG_CHECK(nonce.size() == 16, "GHASH requires a 128-bit nonce");
   auto& n = m_nonce.emplace();
   copy_mem(n, nonce);
   copy_mem(m_ghash, m_H_ad);
}

void GHASH::set_associated_data(std::span<const uint8_t> input) {
   BOTAN_STATE_CHECK(!m_nonce);

   assert_key_material_set();
   m_H_ad = {0};
   ghash_update(m_H_ad, input);
   ghash_zeropad(m_H_ad);
   m_ad_len = input.size();
}

void GHASH::update_associated_data(std::span<const uint8_t> ad) {
   assert_key_material_set();
   ghash_update(m_ghash, ad);
   m_ad_len += ad.size();
}

void GHASH::update(std::span<const uint8_t> input) {
   assert_key_material_set();
   BOTAN_STATE_CHECK(m_nonce);
   ghash_update(m_ghash, input);
   m_text_len += input.size();
}

void GHASH::final(std::span<uint8_t> mac) {
   BOTAN_ARG_CHECK(!mac.empty() && mac.size() <= GCM_BS, "GHASH output length");
   BOTAN_STATE_CHECK(m_nonce);
   assert_key_material_set();

   ghash_zeropad(m_ghash);
   ghash_final_block(m_ghash, m_ad_len, m_text_len);

   xor_buf(mac, std::span{m_ghash}.first(mac.size()), std::span{*m_nonce}.first(mac.size()));

   secure_scrub_memory(m_ghash);
   m_text_len = 0;
   m_nonce.reset();
}

void GHASH::nonce_hash(secure_vector<uint8_t>& y0, std::span<const uint8_t> nonce) {
   assert_key_material_set();
   BOTAN_STATE_CHECK(!m_nonce);
   BOTAN_ARG_CHECK(y0.size() == GCM_BS, "ghash state must be 16 bytes");

   auto sy0 = std::span<uint8_t, GCM_BS>{y0};
   ghash_update(sy0, nonce);
   ghash_zeropad(sy0);
   ghash_final_block(sy0, 0, nonce.size());
}

void GHASH::clear() {
   zap(m_HM);
   reset();
}

void GHASH::reset() {
   m_H_ad = {0};
   secure_scrub_memory(m_ghash);
   if(m_nonce) {
      secure_scrub_memory(m_nonce.value());
      m_nonce.reset();
   }
   m_buffer.clear();
   m_text_len = m_ad_len = 0;
}

void GHASH::ghash_update(std::span<uint8_t, GCM_BS> x, std::span<const uint8_t> input) {
   BufferSlicer in(input);
   while(!in.empty()) {
      if(const auto one_block = m_buffer.handle_unaligned_data(in)) {
         ghash_multiply(x, one_block.value(), 1);
      }

      if(m_buffer.in_alignment()) {
         const auto [aligned_data, full_blocks] = m_buffer.aligned_data_to_process(in);
         if(full_blocks > 0) {
            ghash_multiply(x, aligned_data, full_blocks);
         }
      }
   }
   BOTAN_ASSERT_NOMSG(in.empty());
}

void GHASH::ghash_zeropad(std::span<uint8_t, GCM_BS> x) {
   if(!m_buffer.in_alignment()) {
      m_buffer.fill_up_with_zeros();
      ghash_multiply(x, m_buffer.consume(), 1);
   }
}

void GHASH::ghash_final_block(std::span<uint8_t, GCM_BS> x, uint64_t ad_len, uint64_t text_len) {
   BOTAN_STATE_CHECK(m_buffer.in_alignment());
   const auto final_block = store_be(8 * ad_len, 8 * text_len);
   ghash_multiply(x, final_block, 1);
}

}  // namespace Botan
