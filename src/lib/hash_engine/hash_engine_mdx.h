/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HASH_ENGINE_MDX_H_
#define BOTAN_HASH_ENGINE_MDX_H_

#include <botan/assert.h>
#include <botan/mem_ops.h>
#include <botan/internal/hash_engine.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <algorithm>
#include <array>
#include <concepts>

namespace Botan {

/**
* Generic multi-buffer engine for big-endian Merkle-Damgard hashes
*
* The states buffer passed to the compression function holds the 8
* chaining variables for each lane, as little-endian words in
* variable-major order (all lanes of A, then all lanes of B, ...).
* blocks[l] points to the first of nblocks contiguous blocks for lane l.
*
* The extract function transposes the states into digests, which holds
* the full (untruncated) big-endian digest of each lane in lane order.
*/
template <std::unsigned_integral W>
class MDx_MB_Engine final : public Hash_Engine {
   public:
      using compress_fn = void (*)(uint8_t* states, const uint8_t* const* blocks, size_t nblocks);
      using extract_fn = void (*)(const uint8_t* states, uint8_t* digests);

      MDx_MB_Engine(std::string_view name,
                    size_t output_length,
                    std::span<const uint8_t> common_prefix,
                    std::string_view provider,
                    size_t lanes,
                    size_t block_bytes,
                    size_t ctr_bytes,
                    std::span<const W> midstate,
                    compress_fn compress,
                    extract_fn extract) :
            Hash_Engine(common_prefix),
            m_name(name),
            m_provider(provider),
            m_output_length(output_length),
            m_lanes(lanes),
            m_block_bytes(block_bytes),
            m_ctr_bytes(ctr_bytes),
            m_prefix_full_bytes(common_prefix.size() - common_prefix.size() % block_bytes),
            m_compress(compress),
            m_extract(extract),
            m_initial_states(8 * lanes * sizeof(W)),
            m_states(8 * lanes * sizeof(W)),
            m_digests(8 * lanes * sizeof(W)),
            m_ptrs(lanes) {
         BOTAN_ASSERT_NOMSG(midstate.size() == 8);

         for(size_t j = 0; j != 8; ++j) {
            for(size_t l = 0; l != m_lanes; ++l) {
               store_le(midstate[j], &m_initial_states[(j * m_lanes + l) * sizeof(W)]);
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

         // The logical stream hashed for lane i is
         //   rem || inputs1[i] || inputs2[i] || padding
         // where rem is the part of the prefix not covered by the midstate
         const auto rem = common_prefix().subspan(m_prefix_full_bytes);
         const size_t r = rem.size();
         const size_t len1 = inputs1[0].size();
         const size_t len2 = inputs2.empty() ? 0 : inputs2[0].size();

         // Checked so that the padded length and the offsets derived from
         // it cannot wrap for huge inputs, which matters on 32-bit targets
         const auto padded_end = checked_add(r, len1, len2, 1 + m_ctr_bytes + (m_block_bytes - 1));
         BOTAN_ARG_CHECK(padded_end.has_value(), "Hash_Engine::batch_hash inputs too long");

         const size_t stream_len = r + len1 + len2;
         const size_t blocks = *padded_end / m_block_bytes;
         const size_t padded_len = m_block_bytes * blocks;
         const uint64_t total_bits = 8 * static_cast<uint64_t>(common_prefix().size() + len1 + len2);

         // Ranges of blocks lying entirely within one input are hashed
         // directly from the caller's buffers. All other blocks are
         // assembled in scratch, each in its own slot, since everything
         // in them except the input bytes is the same for every lane.
         const size_t d1_lo = (r + m_block_bytes - 1) / m_block_bytes;
         const size_t d1_hi = (r + len1) / m_block_bytes;
         const size_t d2_lo = (r + len1 + m_block_bytes - 1) / m_block_bytes;
         const size_t d2_hi = (r + len1 + len2) / m_block_bytes;

         std::array<Step, MAX_STEPS> steps{};
         size_t nsteps = 0;
         size_t scratch_blocks = 0;

         for(size_t b = 0; b < blocks;) {
            BOTAN_ASSERT_NOMSG(nsteps < MAX_STEPS);
            Step& step = steps[nsteps++];

            if(b >= d1_lo && b < d1_hi) {
               step = Step{Step::Direct1, b, d1_hi, 0};
            } else if(b >= d2_lo && b < d2_hi) {
               step = Step{Step::Direct2, b, d2_hi, 0};
            } else {
               size_t e = blocks;
               if(b < d1_lo && d1_lo < d1_hi) {
                  e = std::min(e, d1_lo);
               }
               if(b < d2_lo && d2_lo < d2_hi) {
                  e = std::min(e, d2_lo);
               }
               step = Step{Step::Scratch, b, e, scratch_blocks};
               scratch_blocks += e - b;
            }

            b = step.hi;
         }

         const size_t lane_stride = scratch_blocks * m_block_bytes;
         if(m_scratch.size() < m_lanes * lane_stride) {
            m_scratch.resize(m_lanes * lane_stride);
         }
         auto scratch = [&](size_t lane, const Step& step) {
            return &m_scratch[lane * lane_stride + step.slot * m_block_bytes];
         };

         // Write the lane invariant parts of the scratch blocks: the
         // prefix remainder, the padding byte, zeros and the counter
         for(size_t i = 0; i != nsteps; ++i) {
            const Step& step = steps[i];
            if(step.kind != Step::Scratch) {
               continue;
            }
            const size_t lo = step.lo * m_block_bytes;
            const size_t hi = step.hi * m_block_bytes;

            for(size_t l = 0; l != m_lanes; ++l) {
               uint8_t* dest = scratch(l, step);
               clear_mem(dest, hi - lo);
               copy_overlap(dest, lo, hi, rem, 0);
               if(stream_len >= lo && stream_len < hi) {
                  dest[stream_len - lo] = 0x80;
               }
               // Low 8 bytes of the counter; any high bytes stay zero
               if(hi == padded_len) {
                  store_be(total_bits, dest + (padded_len - 8 - lo));
               }
            }
         }

         for(size_t base = 0; base < count; base += m_lanes) {
            // Excess lanes of the last batch just recompute the final message
            auto lane_idx = [&](size_t l) { return std::min(base + l, count - 1); };

            copy_mem(m_states, m_initial_states);

            for(size_t i = 0; i != nsteps; ++i) {
               const Step& step = steps[i];
               const size_t lo = step.lo * m_block_bytes;
               const size_t hi = step.hi * m_block_bytes;

               if(step.kind == Step::Direct1) {
                  for(size_t l = 0; l != m_lanes; ++l) {
                     m_ptrs[l] = inputs1[lane_idx(l)].data() + (lo - r);
                  }
               } else if(step.kind == Step::Direct2) {
                  for(size_t l = 0; l != m_lanes; ++l) {
                     m_ptrs[l] = inputs2[lane_idx(l)].data() + (lo - r - len1);
                  }
               } else {
                  for(size_t l = 0; l != m_lanes; ++l) {
                     uint8_t* dest = scratch(l, step);
                     copy_overlap(dest, lo, hi, inputs1[lane_idx(l)], r);
                     if(!inputs2.empty()) {
                        copy_overlap(dest, lo, hi, inputs2[lane_idx(l)], r + len1);
                     }
                     m_ptrs[l] = dest;
                  }
               }

               m_compress(m_states.data(), m_ptrs.data(), step.hi - step.lo);
            }

            m_extract(m_states.data(), m_digests.data());

            const size_t used_lanes = std::min(m_lanes, count - base);
            for(size_t l = 0; l != used_lanes; ++l) {
               copy_mem(outputs[base + l].first(m_output_length),
                        std::span(m_digests).subspan(l * DIGEST_BYTES, m_output_length));
            }
         }
      }

   private:
      static constexpr size_t DIGEST_BYTES = 8 * sizeof(W);

      /**
      * One range of blocks [lo, hi) of the padded stream, either hashed
      * directly from the first or second input, or from scratch slot
      * slot onwards
      */
      struct Step {
            enum Kind : uint8_t { Direct1, Direct2, Scratch };

            Kind kind;
            size_t lo;
            size_t hi;
            size_t slot;
      };

      // At most scratch, direct1, scratch, direct2, scratch
      static constexpr size_t MAX_STEPS = 5;

      /**
      * Copy the part of src (which starts at offset in the stream) that
      * lies within the stream bytes [lo, hi) to dest
      */
      static void copy_overlap(uint8_t* dest, size_t lo, size_t hi, std::span<const uint8_t> src, size_t offset) {
         const size_t i0 = std::max(lo, offset);
         const size_t i1 = std::min(hi, offset + src.size());
         if(i0 < i1) {
            copy_mem(dest + (i0 - lo), src.data() + (i0 - offset), i1 - i0);
         }
      }

      std::string m_name;
      std::string m_provider;
      size_t m_output_length;
      size_t m_lanes;
      size_t m_block_bytes;
      size_t m_ctr_bytes;
      size_t m_prefix_full_bytes;
      compress_fn m_compress;
      extract_fn m_extract;
      secure_vector<uint8_t> m_initial_states;
      secure_vector<uint8_t> m_states;
      secure_vector<uint8_t> m_digests;
      secure_vector<uint8_t> m_scratch;
      std::vector<const uint8_t*> m_ptrs;
};

}  // namespace Botan

#endif
