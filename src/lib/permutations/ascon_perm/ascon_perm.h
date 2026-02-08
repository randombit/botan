/*
* Permutation Ascon_p[rounds] as specified in NIST SP.800-232, Section 3
* (C) 2025 Jack Lloyd
*     2025 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASCON_PERM_H_
#define BOTAN_ASCON_PERM_H_

#include <botan/internal/sponge.h>
#include <optional>
#include <span>
#include <string>

namespace Botan {

/**
 * Ascon_p as specified in NIST SP.800-232, Section 3
 */
class Ascon_p final : public Sponge<5, uint64_t> {
   public:
      struct Config {
            uint8_t init_and_final_rounds;
            uint8_t processing_rounds;
            uint8_t bit_rate;
            state_t initial_state;
      };

   public:
      consteval explicit Ascon_p(Config config) :
            Sponge({config.bit_rate, config.initial_state}),
            m_init_final_rounds(config.init_and_final_rounds),
            m_processing_rounds(config.processing_rounds) {
         BOTAN_ARG_CHECK(m_init_final_rounds > 0 && m_init_final_rounds <= 16,
                         "Invalid Ascon initialization/finalization rounds");

         BOTAN_ARG_CHECK(m_processing_rounds > 0 && m_processing_rounds <= 16, "Invalid Ascon processing rounds");
      }

      std::string provider() const { return "base"; }

      void absorb(std::span<const uint8_t> input, std::optional<uint8_t> permutation_rounds = std::nullopt);
      void squeeze(std::span<uint8_t> output);
      void percolate_in(std::span<uint8_t> data);
      void percolate_out(std::span<uint8_t> data);

      void finish() { finish(m_init_final_rounds); }

      void intermediate_finish() { finish(m_processing_rounds); }

      void permute() { permute(m_processing_rounds); }

      void initial_permute() { permute(m_init_final_rounds); }

      template <size_t offset, size_t count>
         requires(offset + count <= state_bytes())
      constexpr auto range_of_state() {
         return std::span{state()}.template subspan<offset, count>();
      }

   private:
      void finish(uint8_t rounds);
      void permute(uint8_t rounds);

   private:
      uint8_t m_init_final_rounds;
      uint8_t m_processing_rounds;
};

}  // namespace Botan

#endif
