/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine_keccak.h>

#include <botan/assert.h>
#include <botan/mem_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/scan_name.h>
#include <algorithm>

#if defined(BOTAN_HAS_HASH_ENGINE_KECCAK_AVX2) || defined(BOTAN_HAS_HASH_ENGINE_KECCAK_AVX512) || \
   defined(BOTAN_HAS_HASH_ENGINE_KECCAK_ARMV8)
   #define BOTAN_HASH_ENGINE_KECCAK_HAS_IMPL
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

#if defined(BOTAN_HASH_ENGINE_KECCAK_HAS_IMPL)

namespace {

class Keccak_MB_Engine final : public Hash_Engine {
   public:
      using permute_fn = void (*)(uint64_t* states);
      using absorb_fn = void (*)(uint64_t* states, const uint8_t* const* blocks, size_t rate_words, size_t nblocks);

      /// Number of rate blocks per fused absorb call, keeping the
      /// state in registers across that many permutations
      static constexpr size_t STRIP_BLOCKS = KECCAK_MB_ABSORB_BLOCKS;

      Keccak_MB_Engine(std::string_view name,
                       size_t output_length,
                       size_t rate,
                       uint8_t suffix,
                       std::span<const uint8_t> common_prefix,
                       std::string_view provider,
                       size_t lanes,
                       permute_fn permute,
                       absorb_fn absorb) :
            Hash_Engine(common_prefix),
            m_name(name),
            m_provider(provider),
            m_output_length(output_length),
            m_rate(rate),
            m_suffix(suffix),
            m_lanes(lanes),
            m_permute(permute),
            m_absorb(absorb),
            m_prefix_full_bytes(common_prefix.size() - common_prefix.size() % rate),
            m_midstate(25),
            m_states(25 * lanes),
            m_block_ptrs(STRIP_BLOCKS * lanes),
            m_scratch(STRIP_BLOCKS * lanes * rate) {
         // Absorb any full prefix blocks once, using lane 0 of the kernel
         for(size_t block = 0; block != m_prefix_full_bytes / m_rate; ++block) {
            for(size_t w = 0; w != m_rate / 8; ++w) {
               m_states[w * m_lanes] ^= load_le<uint64_t>(common_prefix.data() + block * m_rate, w);
            }
            m_permute(m_states.data());
         }
         for(size_t w = 0; w != 25; ++w) {
            m_midstate[w] = m_states[w * m_lanes];
         }
      }

      std::string name() const override { return m_name; }

      std::string provider() const override { return m_provider; }

      size_t output_length() const override { return m_output_length; }

      size_t parallelism() const override { return m_lanes; }

      size_t uncached_prefix_bytes() const override { return common_prefix().size() - m_prefix_full_bytes; }

      void batch_hash(std::span<std::span<uint8_t>> outputs,
                      std::span<std::span<const uint8_t>> inputs1,
                      std::span<std::span<const uint8_t>> inputs2) override {
         check_batch_args(outputs, inputs1, inputs2);

         const size_t count = inputs1.size();
         if(count == 0) {
            return;
         }

         // The logical stream absorbed for lane i is
         //   rem || inputs1[i] || inputs2[i] || padding
         // where rem is the part of the prefix not covered by the midstate
         const auto rem = common_prefix().subspan(m_prefix_full_bytes);
         const size_t r = rem.size();
         const size_t len1 = inputs1[0].size();
         const size_t len2 = inputs2.empty() ? 0 : inputs2[0].size();

         // Checked so that the padded length and the offsets derived from
         // it cannot wrap for huge inputs, which matters on 32-bit targets
         BOTAN_ARG_CHECK(checked_add(r, len1, len2, m_rate).has_value(), "Hash_Engine::batch_hash inputs too long");

         const size_t stream_len = r + len1 + len2;
         const size_t blocks = stream_len / m_rate + 1;

         // Ranges of blocks lying entirely within one input, which are
         // absorbed directly from the caller's buffers. All other blocks
         // are assembled into scratch. The final block always contains
         // padding and so is always assembled.
         const size_t d1_lo = (r + m_rate - 1) / m_rate;
         const size_t d1_hi = (r + len1) / m_rate;
         const size_t d2_lo = (r + len1 + m_rate - 1) / m_rate;
         const size_t d2_hi = (r + len1 + len2) / m_rate;

         for(size_t base = 0; base < count; base += m_lanes) {
            // Excess lanes of the last batch just recompute the final message
            auto lane_idx = [&](size_t l) { return std::min(base + l, count - 1); };

            for(size_t w = 0; w != 25; ++w) {
               for(size_t l = 0; l != m_lanes; ++l) {
                  m_states[w * m_lanes + l] = m_midstate[w];
               }
            }

            for(size_t b0 = 0; b0 < blocks; b0 += STRIP_BLOCKS) {
               const size_t strip = std::min(STRIP_BLOCKS, blocks - b0);

               for(size_t bi = 0; bi != strip; ++bi) {
                  const size_t b = b0 + bi;

                  for(size_t l = 0; l != m_lanes; ++l) {
                     const size_t idx = lane_idx(l);

                     const uint8_t* src = nullptr;
                     if(b >= d1_lo && b < d1_hi) {
                        src = inputs1[idx].data() + (m_rate * b - r);
                     } else if(b >= d2_lo && b < d2_hi) {
                        src = inputs2[idx].data() + (m_rate * b - r - len1);
                     } else {
                        uint8_t* slot = &m_scratch[(bi * m_lanes + l) * m_rate];
                        const auto in2 = inputs2.empty() ? std::span<const uint8_t>() : inputs2[idx];
                        assemble(slot, m_rate * b, m_rate * (b + 1), rem, inputs1[idx], in2, stream_len);
                        src = slot;
                     }

                     m_block_ptrs[bi * m_lanes + l] = src;
                  }
               }

               m_absorb(m_states.data(), m_block_ptrs.data(), m_rate / 8, strip);
            }

            const size_t used_lanes = std::min(m_lanes, count - base);

            size_t produced = 0;
            while(true) {
               const size_t take = std::min(m_rate, m_output_length - produced);
               for(size_t l = 0; l != used_lanes; ++l) {
                  extract(outputs[base + l].subspan(produced, take), l);
               }
               produced += take;
               if(produced == m_output_length) {
                  break;
               }
               m_permute(m_states.data());
            }
         }
      }

   private:
      /**
      * Assemble bytes [lo, hi) of the logical padded stream into dest
      */
      void assemble(uint8_t* dest,
                    size_t lo,
                    size_t hi,
                    std::span<const uint8_t> rem,
                    std::span<const uint8_t> in1,
                    std::span<const uint8_t> in2,
                    size_t stream_len) const {
         clear_mem(dest, hi - lo);

         copy_overlap(dest, lo, hi, rem, 0);
         copy_overlap(dest, lo, hi, in1, rem.size());
         copy_overlap(dest, lo, hi, in2, rem.size() + in1.size());

         if(stream_len >= lo && stream_len < hi) {
            dest[stream_len - lo] ^= m_suffix;
         }

         // The final padding bit lands in the last byte of the last block
         if(hi == m_rate * (stream_len / m_rate + 1)) {
            dest[hi - lo - 1] ^= 0x80;
         }
      }

      static void copy_overlap(uint8_t* dest, size_t lo, size_t hi, std::span<const uint8_t> src, size_t offset) {
         const size_t i0 = std::max(lo, offset);
         const size_t i1 = std::min(hi, offset + src.size());
         if(i0 < i1) {
            copy_mem(dest + (i0 - lo), src.data() + (i0 - offset), i1 - i0);
         }
      }

      void extract(std::span<uint8_t> out, size_t lane) const {
         const size_t full_words = out.size() / 8;

         for(size_t w = 0; w != full_words; ++w) {
            store_le(m_states[w * m_lanes + lane], out.data() + 8 * w);
         }

         if(out.size() % 8 != 0) {
            uint8_t last[8];
            store_le(m_states[full_words * m_lanes + lane], last);
            copy_mem(out.data() + 8 * full_words, last, out.size() % 8);
         }
      }

      std::string m_name;
      std::string m_provider;
      size_t m_output_length;
      size_t m_rate;
      uint8_t m_suffix;
      size_t m_lanes;
      permute_fn m_permute;
      absorb_fn m_absorb;
      size_t m_prefix_full_bytes;
      secure_vector<uint64_t> m_midstate;
      secure_vector<uint64_t> m_states;
      std::vector<const uint8_t*> m_block_ptrs;
      secure_vector<uint8_t> m_scratch;
};

}  // namespace

#endif

std::unique_ptr<Hash_Engine> create_keccak_mb_engine(std::string_view hash_fn,
                                                     std::span<const uint8_t> common_prefix,
                                                     std::string_view provider) {
#if defined(BOTAN_HASH_ENGINE_KECCAK_HAS_IMPL)
   size_t output_length = 0;
   size_t rate = 0;
   uint8_t suffix = 0;
   std::string name;

   const SCAN_Name req(hash_fn);
   if((req.algo_name() == "SHAKE-128" || req.algo_name() == "SHAKE-256") && req.arg_count() == 1) {
      const size_t bits = req.arg_as_integer(0);
      if(bits == 0 || bits % 8 != 0) {
         return nullptr;
      }
      output_length = bits / 8;
      rate = (req.algo_name() == "SHAKE-128") ? 168 : 136;
      suffix = 0x1F;
      name = fmt("{}({})", req.algo_name(), bits);
   } else if(req.algo_name() == "SHA-3" && req.arg_count() <= 1) {
      const size_t bits = req.arg_as_integer(0, 512);
      if(bits != 224 && bits != 256 && bits != 384 && bits != 512) {
         return nullptr;
      }
      output_length = bits / 8;
      rate = 200 - 2 * output_length;
      suffix = 0x06;
      name = fmt("SHA-3({})", bits);
   } else {
      return nullptr;
   }

   #if defined(BOTAN_HAS_HASH_ENGINE_KECCAK_ARMV8)
   if(auto feat = CPUID::check(CPUID::Feature::SHA3)) {
      if(provider.empty() || provider == *feat) {
         return std::make_unique<Keccak_MB_Engine>(
            name, output_length, rate, suffix, common_prefix, *feat, 2, keccak_mb_permute_x2, keccak_mb_absorb_x2);
      }
   }
   #endif

   #if defined(BOTAN_HAS_HASH_ENGINE_KECCAK_AVX512)
   if(auto feat = CPUID::check(CPUID::Feature::AVX512)) {
      if(provider.empty() || provider == *feat) {
         return std::make_unique<Keccak_MB_Engine>(
            name, output_length, rate, suffix, common_prefix, *feat, 8, keccak_mb_permute_x8, keccak_mb_absorb_x8);
      }
   }
   #endif

   #if defined(BOTAN_HAS_HASH_ENGINE_KECCAK_AVX2)
   if(auto feat = CPUID::check(CPUID::Feature::AVX2)) {
      if(provider.empty() || provider == *feat) {
         return std::make_unique<Keccak_MB_Engine>(
            name, output_length, rate, suffix, common_prefix, *feat, 4, keccak_mb_permute_x4, keccak_mb_absorb_x4);
      }
   }
   #endif

   return nullptr;
#else
   BOTAN_UNUSED(hash_fn, common_prefix, provider);
   return nullptr;
#endif
}

}  // namespace Botan
