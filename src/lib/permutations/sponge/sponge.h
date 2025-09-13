/*
* Base helper class for implementing sponge constructions like Keccak or Ascon
* (C) 2025 Jack Lloyd
*     2025 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SPONGE_CONSTRUCTION_H_
#define BOTAN_SPONGE_CONSTRUCTION_H_

#include <botan/exceptn.h>
#include <array>

namespace Botan {

/**
 * A generic sponge construction with a fixed state size defined in terms of
 * "words" of an unsigned integral type.
 *
 * This is meant to be used as a base class for specific sponge constructions
 * like Keccak or Ascon.
 */
template <size_t words, std::unsigned_integral word = uint64_t>
class Sponge {
   public:
      using word_t = word;
      using state_t = std::array<word, words>;
      constexpr static size_t word_bytes = sizeof(word);
      constexpr static size_t word_bits = word_bytes * 8;

      struct Config final {
            size_t bit_rate;        /// The number of bits that using algorithms can modify between permutations
            state_t initial_state;  /// The state of the sponge state at initialization
      };

   public:
      constexpr explicit Sponge(Config config) : m_S(config.initial_state), m_S_cursor(0), m_bit_rate(config.bit_rate) {
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

      constexpr auto& state() { return m_S; }

      size_t cursor() const { return m_S_cursor; }

      size_t& _cursor() { return m_S_cursor; }

   protected:
      void reset_cursor() { m_S_cursor = 0; }

   private:
      state_t m_S;
      size_t m_S_cursor;
      size_t m_bit_rate;
};

}  // namespace Botan

#endif
