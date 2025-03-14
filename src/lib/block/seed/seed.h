/*
* SEED
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SEED_H_
#define BOTAN_SEED_H_

#include <botan/block_cipher.h>
#include <botan/secmem.h>

namespace Botan {

/**
* SEED, a Korean block cipher
*/
class SEED final : public Block_Cipher_Fixed_Params<16, 16> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string name() const override { return "SEED"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<SEED>(); }

      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

      secure_vector<uint32_t> m_K;
};

}  // namespace Botan

#endif
