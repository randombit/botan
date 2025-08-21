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
#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include <botan/exceptn.h>

namespace Botan {

using AsconState = std::array<uint64_t, 5>;

struct AsconConfig {
      uint8_t init_and_final_rounds;
      uint8_t processing_rounds;
      uint8_t bit_rate;
      AsconState initial_state;
};

/**
 * Ascon_p as specified in NIST SP.800-232, Section 3
 */
class Ascon_p final {
   public:
      consteval explicit Ascon_p(AsconConfig config) :
            m_S(config.initial_state),
            m_bit_rate(config.bit_rate),
            m_init_final_rounds(config.init_and_final_rounds),
            m_processing_rounds(config.processing_rounds) {
         if(m_bit_rate % 64 != 0 || m_bit_rate > 128) {
            throw Botan::Invalid_Argument("Invalid Ascon bit rate");
         }

         if(m_init_final_rounds > 16) {
            throw Botan::Invalid_Argument("Invalid Ascon initialization/finalization rounds");
         }

         if(m_processing_rounds > 16) {
            throw Botan::Invalid_Argument("Invalid Ascon processing rounds");
         }
      }

      std::string provider() const { return "base"; }

      constexpr size_t capacity() const { return (sizeof(AsconState) * 8) - m_bit_rate; }

      constexpr size_t bit_rate() const { return m_bit_rate; }

      constexpr size_t byte_rate() const { return m_bit_rate / 8; }

      void absorb(std::span<const uint8_t> input, std::optional<uint8_t> permutation_rounds = std::nullopt);
      void squeeze(std::span<uint8_t> output);
      void finish();

   private:
      void permute(uint8_t rounds);

   private:
      AsconState m_S;
      uint8_t m_S_inpos = 0;
      uint8_t m_S_outpos = 0;

      uint8_t m_bit_rate;
      uint8_t m_init_final_rounds;
      uint8_t m_processing_rounds;
};

}  // namespace Botan

#endif
