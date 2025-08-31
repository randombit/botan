/*
* Permutation Ascon_p[rounds] as specified in NIST SP.800-232, Section 3
* (C) 2025 Jack Lloyd
*     2025 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASCON_PERM_H_
#define BOTAN_ASCON_PERM_H_

#include <array>
#include <optional>
#include <span>
#include <string>

#include <botan/exceptn.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

namespace Botan {

template <size_t words, std::unsigned_integral word = uint64_t>
class Sponge {
   protected:
      using state_t = std::array<word, words>;
      constexpr static size_t word_bytes = sizeof(word);
      constexpr static size_t word_bits = word_bytes * 8;

      struct PartialWordBounds {
            size_t offset;  // NOLINT(*-non-private-member-*)
            size_t length;  // NOLINT(*-non-private-member-*)

            word mask() const { return ((word(0) - 1) >> ((word_bytes - length) * 8)) << (offset * 8); }
      };

   public:
      struct SpongeConfig {
            size_t bit_rate;
            state_t initial_state;
      };

   public:
      consteval explicit Sponge(const SpongeConfig& config) :
            m_S(config.initial_state), m_S_cursor(0), m_bit_rate(config.bit_rate) {
         if(m_bit_rate % (sizeof(word) * 8) != 0 || m_bit_rate > words * sizeof(word) * 8) {
            throw Botan::Invalid_Argument("Invalid sponge bit rate");
         }
      }

      constexpr static size_t state_bytes() { return sizeof(state_t); }

      constexpr static size_t state_bits() { return state_bytes() * 8; }

      constexpr size_t bit_rate() const { return m_bit_rate; }

      constexpr size_t byte_rate() const { return m_bit_rate / 8; }

      constexpr size_t bit_capacity() const { return state_bits() - bit_rate(); }

      constexpr size_t byte_capacity() const { return state_bytes() - byte_rate(); }

      std::string provider() const { return "base"; }

      constexpr auto& state() { return m_S; }

      template <size_t offset, size_t count>
         requires(offset + count <= state_bytes())
      constexpr auto range_of_state() {
         return std::span{m_S}.template subspan<offset, count>();
      }

   protected:
      uint8_t cursor() const { return m_S_cursor; }

      template <std::invocable<word&, word> WordModifierFnT,
                std::invocable<word&, word, PartialWordBounds> PartialWordModifierFnT,
                std::invocable PermutationFnT>
      void process(std::span<const uint8_t> input,
                   WordModifierFnT word_modifier_fn,
                   PartialWordModifierFnT partial_word_modifier_fn,
                   PermutationFnT permutation_fn) {
         BufferSlicer input_slicer(input);

         // Block-wise incorporation of the input data into the sponge state until
         // all input bytes are processed
         while(!input_slicer.empty()) {
            const size_t to_take_this_round = std::min(input_slicer.remaining(), byte_rate() - m_S_cursor);
            BufferSlicer input_this_round(input_slicer.take(to_take_this_round));

            // If necessary, try to get aligned with the sponge state's 64-bit integer array
            const auto bytes_out_of_word_alignment = static_cast<size_t>(m_S_cursor % word_bytes);
            if(bytes_out_of_word_alignment > 0) {
               const auto bytes_until_word_alignment = word_bytes - bytes_out_of_word_alignment;
               const auto bytes_from_input = std::min(input_this_round.remaining(), bytes_until_word_alignment);
               BOTAN_DEBUG_ASSERT(bytes_from_input < word_bytes);

               std::array<uint8_t, word_bytes> partial_word{};
               input_this_round.copy_into(
                  std::span{partial_word}.subspan(bytes_out_of_word_alignment, bytes_from_input));
               partial_word_modifier_fn(m_S[m_S_cursor / word_bytes],
                                        load_le(partial_word),
                                        {
                                           .offset = bytes_out_of_word_alignment,
                                           .length = bytes_from_input,
                                        });
               m_S_cursor += bytes_from_input;
            }

            // Process as many aligned 64-bit integer values as possible
            for(; input_this_round.remaining() >= word_bytes; m_S_cursor += word_bytes) {
               word_modifier_fn(m_S[m_S_cursor / word_bytes], load_le(input_this_round.take<word_bytes>()));
            }

            // Read remaining input data, causing misalignment, if necessary
            const auto remaining_bytes_out_of_word_alignment = input_this_round.remaining();
            BOTAN_DEBUG_ASSERT(remaining_bytes_out_of_word_alignment < word_bytes);
            if(remaining_bytes_out_of_word_alignment > 0) {
               std::array<uint8_t, word_bytes> partial_word{};
               input_this_round.copy_into(std::span{partial_word}.first(remaining_bytes_out_of_word_alignment));
               partial_word_modifier_fn(m_S[m_S_cursor / word_bytes],
                                        load_le(partial_word),
                                        {
                                           .offset = 0,
                                           .length = remaining_bytes_out_of_word_alignment,
                                        });
               m_S_cursor += remaining_bytes_out_of_word_alignment;
            }

            // We reached the end of a sponge state block... permute() and start over
            if(m_S_cursor == byte_rate()) {
               permutation_fn();
               m_S_cursor = 0;
            }
         }
      }

   private:
      std::array<word, words> m_S;
      uint8_t m_S_cursor;
      uint8_t m_bit_rate;
};

/**
 * Ascon_p as specified in NIST SP.800-232, Section 3
 */
class Ascon_p final : public Sponge<5, uint64_t> {
   public:
      struct AsconConfig : public Sponge::SpongeConfig {
            uint8_t init_and_final_rounds;
            uint8_t processing_rounds;
      };

      consteval explicit Ascon_p(const AsconConfig& config) :
            Sponge(config),
            m_init_final_rounds(config.init_and_final_rounds),
            m_processing_rounds(config.processing_rounds) {
         if(m_init_final_rounds > 16) {
            throw Botan::Invalid_Argument("Invalid Ascon initialization/finalization rounds");
         }

         if(m_processing_rounds > 16) {
            throw Botan::Invalid_Argument("Invalid Ascon processing rounds");
         }
      }

      void permute() { permute(m_init_final_rounds); }

      void absorb(std::span<const uint8_t> input, std::optional<uint8_t> permutation_rounds = std::nullopt);
      void percolate_in(std::span<uint8_t> data);
      void percolate_out(std::span<uint8_t> data);
      void squeeze(std::span<uint8_t> output);

      void finish();
      void intermediate_finish();

   private:
      void permute(uint8_t rounds);

   private:
      uint8_t m_init_final_rounds;
      uint8_t m_processing_rounds;
};

}  // namespace Botan

#endif
