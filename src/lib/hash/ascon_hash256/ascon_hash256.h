/*
* Ascon-Hash256 (NIST SP.800-232)
* (C) 2025 Jack Lloyd
*     2025 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASCON_HASH256_H_
#define BOTAN_ASCON_HASH256_H_

#include <botan/hash.h>
#include <botan/internal/ascon_perm.h>

namespace Botan {

/**
* Ascon-Hash256 (NIST SP.800-232 Section 5.1)
*/
class Ascon_Hash256 final : public HashFunction {
   public:
      Ascon_Hash256();

      size_t output_length() const override { return 32; }

      std::string name() const override { return "Ascon-Hash256"; }

      std::string provider() const override { return m_ascon_p.provider(); }

      void clear() override;

      std::unique_ptr<HashFunction> new_object() const override;
      std::unique_ptr<HashFunction> copy_state() const override;

   private:
      void add_data(std::span<const uint8_t> input) override;
      void final_result(std::span<uint8_t> out) override;

   private:
      Ascon_p m_ascon_p;
};

}  // namespace Botan

#endif
