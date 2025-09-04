/*
* Byte-oriented Sponge processing helpers
* (C) 2025 Jack Lloyd
*     2025 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SPONGE_PROCESSOR_H_
#define BOTAN_SPONGE_PROCESSOR_H_

#include <array>
#include <span>

#include <botan/exceptn.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

namespace Botan {

template <typename SpongeT, std::invocable PermutationFnT>
class SpongeProcessor {
   public:
      using state_t = typename SpongeT::state_t;
      using word_t = typename SpongeT::word_t;

      constexpr static size_t word_bytes = SpongeT::word_bytes;
      constexpr static size_t word_bits = SpongeT::word_bits;

      struct PartialWordBounds final {
            size_t offset;  // NOLINT(*-non-private-member-*)
            size_t length;  // NOLINT(*-non-private-member-*)

            word_t read_from(BufferSlicer& slicer) const {
               std::array<uint8_t, word_bytes> partial_word_bytes{};
               slicer.copy_into(std::span{partial_word_bytes}.subspan(offset, length));
               return load_le(partial_word_bytes);
            }

            void write_into(BufferStuffer& stuffer, word_t partial_word) const {
               const auto partial_word_bytes = store_le(partial_word);
               stuffer.append(std::span{partial_word_bytes}.subspan(offset, length));
            }

            word_t masked_assignment(word_t state_word, word_t partial_input_word) const {
               const auto mask = ((word_t(0) - 1) >> ((word_bytes - length) * 8)) << (offset * 8);
               return (state_word & ~mask) | (partial_input_word & mask);
            }
      };

      class FullWordBounds final {
         public:
            word_t read_from(BufferSlicer& slicer) const { return load_le(slicer.take<word_bytes>()); }

            void write_into(BufferStuffer& stuffer, word_t full_word) const { stuffer.append(store_le(full_word)); }

            word_t masked_assignment(word_t, word_t full_input_word) const { return full_input_word; }
      };

   public:
      explicit SpongeProcessor(SpongeT& sponge, PermutationFnT permutation_fn) :
            m_sponge(sponge), m_permutation_fn(permutation_fn) {}

   public:
      template <typename WordModifierFnT>
      void process(size_t bytes_to_process, WordModifierFnT word_modifier_fn) {
         const auto byte_rate = m_sponge.byte_rate();
         auto& S = m_sponge.state();
         auto& cursor = m_sponge._cursor();

         // Block-wise incorporation of the input data into the sponge state until
         // all input bytes are processed
         while(bytes_to_process > 0) {
            const size_t bytes_this_round = std::min(bytes_to_process, byte_rate - cursor);
            size_t bytes_to_process_this_round = bytes_this_round;

            // If necessary, try to get aligned with the sponge state's 64-bit integer array
            const auto bytes_out_of_word_alignment = static_cast<size_t>(cursor % word_bytes);
            if(bytes_out_of_word_alignment > 0) {
               const auto bytes_until_word_alignment = word_bytes - bytes_out_of_word_alignment;
               const auto bytes_from_input = std::min(bytes_to_process_this_round, bytes_until_word_alignment);
               BOTAN_DEBUG_ASSERT(bytes_from_input < word_bytes);

               S[cursor / word_bytes] = word_modifier_fn(S[cursor / word_bytes],
                                                         PartialWordBounds{
                                                            .offset = bytes_out_of_word_alignment,
                                                            .length = bytes_from_input,
                                                         });
               cursor += bytes_from_input;
               bytes_to_process_this_round -= bytes_from_input;
            }

            // Process as many aligned 64-bit integer values as possible
            for(; bytes_to_process_this_round >= word_bytes;
                cursor += word_bytes, bytes_to_process_this_round -= word_bytes) {
               S[cursor / word_bytes] = word_modifier_fn(S[cursor / word_bytes], FullWordBounds{});
            }

            // Read remaining input data, causing misalignment, if necessary
            BOTAN_DEBUG_ASSERT(bytes_to_process_this_round < word_bytes);
            if(bytes_to_process_this_round > 0) {
               S[cursor / word_bytes] = word_modifier_fn(S[cursor / word_bytes],
                                                         PartialWordBounds{
                                                            .offset = 0,
                                                            .length = bytes_to_process_this_round,
                                                         });
               cursor += bytes_to_process_this_round;
               bytes_to_process_this_round = 0;
            }

            // We reached the end of a sponge state block... permute() and start over
            BOTAN_DEBUG_ASSERT(bytes_to_process_this_round == 0);
            if(cursor == byte_rate) {
               m_permutation_fn();
               cursor = 0;
            }

            bytes_to_process -= bytes_this_round;
         }
      }

      void absorb(std::span<const uint8_t> input) {
         BufferSlicer input_slicer(input);
         process(input.size(),
                 [&](word_t state_word, auto bounds) { return state_word ^ bounds.read_from(input_slicer); });
         BOTAN_ASSERT_NOMSG(input_slicer.empty());
      }

      void squeeze(std::span<uint8_t> output) {
         BufferStuffer output_stuffer(output);
         process(output.size(), [&](word_t state_word, auto bounds) {
            bounds.write_into(output_stuffer, state_word);
            return state_word;
         });
         BOTAN_ASSERT_NOMSG(output_stuffer.full());
      }

   private:
      SpongeT& m_sponge;
      PermutationFnT m_permutation_fn;
};

}  // namespace Botan

#endif
