/*
* Permutation Ascon_p[rounds] as specified in NIST SP.800-232, Section 3
* (C) 2025 Jack Lloyd
*     2025 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASCON_PERM_H_
#define BOTAN_ASCON_PERM_H_

#include <optional>
#include <string>

#include <botan/internal/sponge.h>

namespace Botan {

/**
 * Ascon_p as specified in NIST SP.800-232, Section 3
 */
class Ascon_p final : public Sponge<5, uint64_t> {
   public:
      struct AsconConfig {
            uint8_t init_and_final_rounds;
            uint8_t processing_rounds;
      };

      consteval explicit Ascon_p(SpongeConfig sponge_config, AsconConfig ascon_config) :
            Sponge(sponge_config),
            m_init_final_rounds(ascon_config.init_and_final_rounds),
            m_processing_rounds(ascon_config.processing_rounds) {
         if(m_init_final_rounds > 16) {
            throw Botan::Invalid_Argument("Invalid Ascon initialization/finalization rounds");
         }

         if(m_processing_rounds > 16) {
            throw Botan::Invalid_Argument("Invalid Ascon processing rounds");
         }
      }

      std::string provider() const { return "base"; }

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
