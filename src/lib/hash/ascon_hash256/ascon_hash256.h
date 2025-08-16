/*
* Ascon-Hash256 (NIST SP.800-232)
* (C) 2025 Jack Lloyd
*.    2025 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASCON_HASH256_H_
#define BOTAN_ASCON_HASH256_H_

#include <botan/hash.h>
#include <botan/secmem.h>
#include <botan/internal/ascon_perm.h>
#include <string>

namespace Botan {

/**
* Ascon-Hash256 (NIST SP.800-232 Section 5.1)
*/
class Ascon_Hash256 : public HashFunction {
   public:
      explicit Ascon_Hash256();

      size_t hash_block_size() const override { return m_ascon_p.byte_rate(); }

      size_t output_length() const override { return 32; }

      std::string name() const override { return "Ascon-Hash256"; }

      void clear() override { init(); }

      std::unique_ptr<HashFunction> new_object() const override;
      std::unique_ptr<HashFunction> copy_state() const override;

      std::string provider() const override;

   private:
      void add_data(std::span<const uint8_t> input) override;
      void final_result(std::span<uint8_t> out) override;

      void init();

   private:
      constexpr static uint64_t IV = 0x0000080100cc0002;
      Ascon_p<12, IV> m_ascon_p;
};

}  // namespace Botan

#endif
