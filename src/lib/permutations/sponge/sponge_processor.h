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
      constexpr static size_t word_bytes = SpongeT::word_bytes;
      constexpr static size_t word_bits = SpongeT::word_bits;

      struct PartialWordBounds final {
            size_t offset;  // NOLINT(*-non-private-member-*)
            size_t length;  // NOLINT(*-non-private-member-*)

            word mask() const { return ((word(0) - 1) >> ((word_bytes - length) * 8)) << (offset * 8); }
      };

   public:
      explicit SpongeProcessor(SpongeT& sponge, PermutationFnT permutation_fn) :
            m_sponge(sponge), m_permutation_fn(permutation_fn) {}

   public:
      template <std::invocable<word&, word> WordModifierFnT,
                std::invocable<word&, word, PartialWordBounds> PartialWordModifierFnT>
      void process(std::span<const uint8_t> input,
                   WordModifierFnT word_modifier_fn,
                   PartialWordModifierFnT partial_word_modifier_fn) {
         const auto byte_rate = m_sponge.byte_rate();
         auto& S = m_sponge.state();
         auto& cursor = m_sponge._cursor();

         BufferSlicer input_slicer(input);

         // Block-wise incorporation of the input data into the sponge state until
         // all input bytes are processed
         while(!input_slicer.empty()) {
            const size_t to_take_this_round = std::min(input_slicer.remaining(), byte_rate - cursor);
            BufferSlicer input_this_round(input_slicer.take(to_take_this_round));

            // If necessary, try to get aligned with the sponge state's 64-bit integer array
            const auto bytes_out_of_word_alignment = static_cast<size_t>(cursor % word_bytes);
            if(bytes_out_of_word_alignment > 0) {
               const auto bytes_until_word_alignment = word_bytes - bytes_out_of_word_alignment;
               const auto bytes_from_input = std::min(input_this_round.remaining(), bytes_until_word_alignment);
               BOTAN_DEBUG_ASSERT(bytes_from_input < word_bytes);

               std::array<uint8_t, word_bytes> partial_word{};
               input_this_round.copy_into(
                  std::span{partial_word}.subspan(bytes_out_of_word_alignment, bytes_from_input));
               partial_word_modifier_fn(S[cursor / word_bytes],
                                        load_le(partial_word),
                                        PartialWordBounds{
                                           .offset = bytes_out_of_word_alignment,
                                           .length = bytes_from_input,
                                        });
               cursor += static_cast<uint8_t>(bytes_from_input);
            }

            // Process as many aligned 64-bit integer values as possible
            for(; input_this_round.remaining() >= word_bytes; cursor += word_bytes) {
               word_modifier_fn(S[cursor / word_bytes], load_le(input_this_round.take<word_bytes>()));
            }

            // Read remaining input data, causing misalignment, if necessary
            const auto remaining_bytes_out_of_word_alignment = input_this_round.remaining();
            BOTAN_DEBUG_ASSERT(remaining_bytes_out_of_word_alignment < word_bytes);
            if(remaining_bytes_out_of_word_alignment > 0) {
               std::array<uint8_t, word_bytes> partial_word{};
               input_this_round.copy_into(std::span{partial_word}.first(remaining_bytes_out_of_word_alignment));
               partial_word_modifier_fn(S[cursor / word_bytes],
                                        load_le(partial_word),
                                        PartialWordBounds{
                                           .offset = 0,
                                           .length = remaining_bytes_out_of_word_alignment,
                                        });
               cursor += static_cast<uint8_t>(remaining_bytes_out_of_word_alignment);
            }

            // We reached the end of a sponge state block... permute() and start over
            if(cursor == byte_rate) {
               m_permutation_fn();
               cursor = 0;
            }
         }
      }

      void absorb(std::span<const uint8_t> input) {
         process(
            input,
            [](uint64_t& state_word, uint64_t input_word) { state_word ^= input_word; },
            [](uint64_t& state_word, uint64_t input_word, PartialWordBounds) { state_word ^= input_word; });
      }

      void squeeze(std::span<uint8_t> output) {
         BufferStuffer output_stuffer(output);

         process(
            output,
            [&](uint64_t& state_word, uint64_t) { output_stuffer.append(store_le(state_word)); },
            [&](uint64_t& state_word, uint64_t, PartialWordBounds bounds) {
               const auto out_buffer = store_le(state_word);
               output_stuffer.append(std::span{out_buffer}.subspan(bounds.offset, bounds.length));
            });
      }

   private:
      SpongeT& m_sponge;
      PermutationFnT m_permutation_fn;
};

}  // namespace Botan

#endif
