/*
* POLYVAL hash function (RFC 8452)
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/polyval.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/ghash.h>
#include <botan/internal/loadstor.h>

#if defined(BOTAN_HAS_CPUID)
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

namespace {

std::array<uint8_t, 16> byte_reverse(std::span<const uint8_t, 16> x) {
   const auto w = load_le<std::array<uint64_t, 2>>(x);
   return store_be(w[1], w[0]);
}

}  // namespace

std::string Polyval::provider() const {
#if defined(BOTAN_HAS_GHASH_AVX512_CLMUL)
   if(auto feat = CPUID::check(CPUID::Feature::AVX512_CLMUL)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_GHASH_CLMUL_CPU)
   if(auto feat = CPUID::check(CPUID::Feature::HW_CLMUL)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_GHASH_CLMUL_VPERM)
   if(auto feat = CPUID::check(CPUID::Feature::SIMD_4X32)) {
      return *feat;
   }
#endif

   return "base";
}

bool Polyval::has_keying_material() const {
   return !m_HM.empty() || !m_H_pow.empty();
}

void Polyval::key_schedule(std::span<const uint8_t> key) {
   m_state = {0};
   m_buffer.clear();

   BOTAN_ASSERT_NOMSG(key.size() == BS);

#if defined(BOTAN_HAS_GHASH_AVX512_CLMUL)
   if(CPUID::has(CPUID::Feature::AVX512_CLMUL)) {
      zap(m_HM);
      if(m_H_pow.size() != 32) {
         m_H_pow.resize(32);
      }
      polyval_precompute_avx512_clmul(key.data(), m_H_pow.data());
      return;
   }
#endif

#if defined(BOTAN_HAS_GHASH_CLMUL_CPU)
   if(CPUID::has(CPUID::Feature::HW_CLMUL)) {
      zap(m_HM);
      polyval_precompute_cpu(key.data(), m_H_pow);
      return;
   }
#endif

   /*
   The fallback reuses the GHASH tables, relying on RFC 8452 Section 3:

   "We note that POLYVAL(H, X_1, X_2, ...) is equal to
   ByteReverse(GHASH(ByteReverse(H) * x, ByteReverse(X_1),
   ByteReverse(X_2), ...)), where ByteReverse is a function that
   reverses the order of 16 bytes."
   */
   zap(m_H_pow);
   auto H = load_le<std::array<uint64_t, 2>>(key.first<BS>());
   // Byte reversing the key swaps the words and bswaps each; then multiply
   // by x in the GHASH convention, carrying out of the bottom bit
   std::swap(H[0], H[1]);
   const uint64_t R = 0xE100000000000000;
   const uint64_t carry = CT::Mask<uint64_t>::expand(H[1] & 1).if_set_return(R);
   H[1] = (H[1] >> 1) | (H[0] << 63);
   H[0] = (H[0] >> 1) ^ carry;
   const auto Hx = store_be(H[0], H[1]);
   GHASH::ghash_precompute_base(Hx, m_HM);
}

void Polyval::update(std::span<const uint8_t> input) {
   assert_key_material_set();
   BufferSlicer in(input);
   while(!in.empty()) {
      if(const auto one_block = m_buffer.handle_unaligned_data(in)) {
         polyval_multiply(m_state, one_block.value(), 1);
      }

      if(m_buffer.in_alignment()) {
         const auto [aligned_data, full_blocks] = m_buffer.aligned_data_to_process(in);
         if(full_blocks > 0) {
            polyval_multiply(m_state, aligned_data, full_blocks);
         }
      }
   }
   BOTAN_ASSERT_NOMSG(in.empty());
}

void Polyval::zero_pad() {
   assert_key_material_set();
   if(!m_buffer.in_alignment()) {
      m_buffer.fill_up_with_zeros();
      polyval_multiply(m_state, m_buffer.consume(), 1);
   }
}

void Polyval::final(std::span<uint8_t, BS> out) {
   assert_key_material_set();
   BOTAN_STATE_CHECK(m_buffer.in_alignment());

   if(m_H_pow.empty()) {
      // Fallback path; the state is in the GHASH byte order
      copy_mem(out, byte_reverse(m_state));
   } else {
      copy_mem(out, m_state);
   }

   secure_scrub_memory(m_state);
}

void Polyval::clear() {
   zap(m_HM);
   zap(m_H_pow);
   secure_scrub_memory(m_state);
   m_buffer.clear();
}

void Polyval::polyval_multiply(std::span<uint8_t, BS> x, std::span<const uint8_t> input, size_t blocks) {
   BOTAN_ASSERT_NOMSG(input.size() % BS == 0);

#if defined(BOTAN_HAS_GHASH_AVX512_CLMUL)
   if(CPUID::has(CPUID::Feature::AVX512_CLMUL)) {
      BOTAN_ASSERT_NOMSG(m_H_pow.size() == 32);
      return polyval_multiply_avx512_clmul(x.data(), m_H_pow.data(), input.data(), blocks);
   }
#endif

#if defined(BOTAN_HAS_GHASH_CLMUL_CPU)
   if(CPUID::has(CPUID::Feature::HW_CLMUL)) {
      BOTAN_ASSERT_NOMSG(!m_H_pow.empty());
      return polyval_multiply_cpu(x.data(), m_H_pow, input.data(), blocks);
   }
#endif

   // Fallback via GHASH (see key_schedule); each input block is byte
   // reversed, and the state is maintained in the GHASH byte order
   BufferSlicer in(input);
   for(size_t b = 0; b != blocks; ++b) {
      const auto rev = byte_reverse(in.take<BS>());

#if defined(BOTAN_HAS_GHASH_CLMUL_VPERM)
      if(CPUID::has(CPUID::Feature::SIMD_2X64)) {
         BOTAN_ASSERT_NOMSG(!m_HM.empty());
         GHASH::ghash_multiply_vperm(x.data(), m_HM.data(), rev.data(), 1);
         continue;
      }
#endif

      GHASH::ghash_multiply_base(x, m_HM, rev, 1);
   }
}

}  // namespace Botan
