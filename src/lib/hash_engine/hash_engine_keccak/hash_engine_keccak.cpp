/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine_keccak.h>

#include <botan/assert.h>
#include <botan/mem_ops.h>
#include <botan/internal/algorithm_spec.h>
#include <botan/internal/fmt.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <algorithm>
#include <array>

#if defined(BOTAN_HAS_HASH_ENGINE_KECCAK_AVX2) || defined(BOTAN_HAS_HASH_ENGINE_KECCAK_AVX512)
   #define BOTAN_HASH_ENGINE_KECCAK_HAS_IMPL
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

#if defined(BOTAN_HASH_ENGINE_KECCAK_HAS_IMPL)

namespace {

class Keccak_MB_Engine final : public Hash_Engine {
   public:
      using permute_fn = void (*)(uint64_t* states);
      using absorb_fn = void (*)(
         uint64_t* states, const uint64_t* states_in, const uint8_t* const* blocks, size_t rate_words, size_t nblocks);

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
            m_initial_states(25 * lanes),
            m_states(25 * lanes),
            m_block_ptrs(STRIP_BLOCKS * lanes) {
         // Absorb any full prefix blocks once, using lane 0 of the kernel
         for(size_t block = 0; block != m_prefix_full_bytes / m_rate; ++block) {
            for(size_t w = 0; w != m_rate / 8; ++w) {
               m_states[w * m_lanes] ^= load_le<uint64_t>(common_prefix.data() + block * m_rate, w);
            }
            m_permute(m_states.data());
         }
         for(size_t w = 0; w != 25; ++w) {
            for(size_t l = 0; l != m_lanes; ++l) {
               m_initial_states[w * m_lanes + l] = m_states[w * m_lanes];
            }
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

         // Ranges of blocks lying entirely within one input are absorbed
         // directly from the caller's buffers. All other blocks are
         // assembled in scratch, each in its own slot, since everything in
         // them except the input bytes is the same for every lane. The
         // final block always contains padding and so is always assembled.
         const size_t d1_lo = (r + m_rate - 1) / m_rate;
         const size_t d1_hi = (r + len1) / m_rate;
         const size_t d2_lo = (r + len1 + m_rate - 1) / m_rate;
         const size_t d2_hi = (r + len1 + len2) / m_rate;

         std::array<Step, MAX_STEPS> steps{};
         size_t nsteps = 0;
         size_t scratch_blocks = 0;

         for(size_t b = 0; b < blocks;) {
            BOTAN_ASSERT_NOMSG(nsteps < MAX_STEPS);
            Step& step = steps[nsteps++];

            if(b >= d1_lo && b < d1_hi) {
               step = Step{Step::Kind::Direct1, b, d1_hi, 0};
            } else if(b >= d2_lo && b < d2_hi) {
               step = Step{Step::Kind::Direct2, b, d2_hi, 0};
            } else {
               size_t e = blocks;
               if(b < d1_lo && d1_lo < d1_hi) {
                  e = std::min(e, d1_lo);
               }
               if(b < d2_lo && d2_lo < d2_hi) {
                  e = std::min(e, d2_lo);
               }
               step = Step{Step::Kind::Scratch, b, e, scratch_blocks};
               scratch_blocks += e - b;
            }

            b = step.hi;
         }

         const size_t lane_stride = scratch_blocks * m_rate;
         if(m_scratch.size() < m_lanes * lane_stride) {
            m_scratch.resize(m_lanes * lane_stride);
         }
         const auto scratch = [&](size_t lane, const Step& step, size_t b) {
            return &m_scratch[lane * lane_stride + (step.slot + b - step.lo) * m_rate];
         };

         // Write the lane invariant parts of the scratch blocks: the
         // prefix remainder, the padding and zeros
         for(size_t i = 0; i != nsteps; ++i) {
            const Step& step = steps[i];
            if(step.kind != Step::Kind::Scratch) {
               continue;
            }
            for(size_t b = step.lo; b != step.hi; ++b) {
               for(size_t l = 0; l != m_lanes; ++l) {
                  assemble(scratch(l, step, b), m_rate * b, m_rate * (b + 1), rem, stream_len);
               }
            }
         }

         for(size_t base = 0; base < count; base += m_lanes) {
            // Excess lanes of the last batch just recompute the final message
            const auto lane_idx = [&](size_t l) { return std::min(base + l, count - 1); };

            size_t si = 0;
            for(size_t b0 = 0; b0 < blocks; b0 += STRIP_BLOCKS) {
               const size_t strip = std::min(STRIP_BLOCKS, blocks - b0);

               for(size_t bi = 0; bi != strip; ++bi) {
                  const size_t b = b0 + bi;
                  while(b >= steps[si].hi) {
                     ++si;
                  }
                  const Step& step = steps[si];
                  const size_t lo = m_rate * b;
                  const size_t hi = m_rate * (b + 1);

                  for(size_t l = 0; l != m_lanes; ++l) {
                     const size_t idx = lane_idx(l);

                     const uint8_t* src = nullptr;
                     if(step.kind == Step::Kind::Direct1) {
                        src = inputs1[idx].data() + (lo - r);
                     } else if(step.kind == Step::Kind::Direct2) {
                        src = inputs2[idx].data() + (lo - r - len1);
                     } else {
                        uint8_t* slot = scratch(l, step, b);
                        copy_overlap(slot, lo, hi, inputs1[idx], r);
                        if(!inputs2.empty()) {
                           copy_overlap(slot, lo, hi, inputs2[idx], r + len1);
                        }
                        src = slot;
                     }

                     m_block_ptrs[bi * m_lanes + l] = src;
                  }
               }

               // The first strip starts from the initial states
               const uint64_t* states_in = (b0 == 0) ? m_initial_states.data() : m_states.data();
               m_absorb(m_states.data(), states_in, m_block_ptrs.data(), m_rate / 8, strip);
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
      * One range of blocks [lo, hi) of the padded stream, either absorbed
      * directly from the first or second input, or from scratch slot
      * slot onwards
      */
      struct Step {
            enum class Kind : uint8_t { Direct1, Direct2, Scratch };

            Kind kind;
            size_t lo;
            size_t hi;
            size_t slot;
      };

      // At most scratch, direct1, scratch, direct2, scratch
      static constexpr size_t MAX_STEPS = 5;

      /**
      * Assemble the lane invariant bytes [lo, hi) of the logical padded
      * stream into dest, leaving zeros where the inputs go
      */
      void assemble(uint8_t* dest, size_t lo, size_t hi, std::span<const uint8_t> rem, size_t stream_len) const {
         clear_mem(dest, hi - lo);

         copy_overlap(dest, lo, hi, rem, 0);

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
            copy_short(dest + (i0 - lo), src.data() + (i0 - offset), i1 - i0);
         }
      }

      void extract(std::span<uint8_t> out, size_t lane) const {
         // Locals, since stores through out could otherwise alias the members
         const uint64_t* states = m_states.data() + lane;
         const size_t lanes = m_lanes;
         const size_t full_words = out.size() / 8;

         for(size_t w = 0; w != full_words; ++w) {
            store_le(states[w * lanes], out.data() + 8 * w);
         }

         if(out.size() % 8 != 0) {
            uint8_t last[8];
            store_le(states[full_words * lanes], last);
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
      secure_vector<uint64_t> m_initial_states;
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

   const AlgorithmSpec req(hash_fn);
   if(auto shake = req.match("SHAKE-128|SHAKE-256({bits:int})")) {
      const size_t bits = shake->integer("bits");
      if(bits == 0 || bits % 8 != 0) {
         return nullptr;
      }
      output_length = bits / 8;
      rate = (shake->head() == "SHAKE-128") ? 168 : 136;
      suffix = 0x1F;
      name = fmt("{}({})", shake->head(), bits);
   } else if(auto sha3 = req.match("SHA-3({bits:int=512})")) {
      const size_t bits = sha3->integer("bits");
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
