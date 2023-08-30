/*
* Noekeon
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_NOEKEON_H_
#define BOTAN_NOEKEON_H_

#include <botan/block_cipher.h>

namespace Botan {

/**
* Noekeon
*/
class Noekeon final : public Block_Cipher_Fixed_Params<16, 16> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      std::string provider() const override;
      void clear() override;

      std::string name() const override { return "Noekeon"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<Noekeon>(); }

      size_t parallelism() const override;
      bool has_keying_material() const override;

   private:
#if defined(BOTAN_HAS_NOEKEON_SIMD)
      void simd_encrypt_4(const uint8_t in[], uint8_t out[]) const;
      void simd_decrypt_4(const uint8_t in[], uint8_t out[]) const;
#endif

      /**
      * The Noekeon round constants
      */
      static const uint8_t RC[17];

      void key_schedule(std::span<const uint8_t> key) override;
      secure_vector<uint32_t> m_EK, m_DK;
};

}  // namespace Botan

#endif
