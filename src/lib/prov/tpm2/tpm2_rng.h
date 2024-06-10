/*
* TPM 2 RNG interface
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_RNG_H_
#define BOTAN_TPM2_RNG_H_

#include <botan/rng.h>

#include <botan/tpm2.h>

namespace Botan {
class BOTAN_PUBLIC_API(3, 6) TPM2_RNG final : public Hardware_RNG {
   public:
      TPM2_RNG(std::shared_ptr<TPM2_Context> ctx) : m_ctx(std::move(ctx)) {}

      bool accepts_input() const override { return true; }

      std::string name() const override { return "TPM2_RNG"; }

      bool is_seeded() const override { return true; }

   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) override;

   private:
      std::shared_ptr<TPM2_Context> m_ctx;
};

}  // namespace Botan

#endif
