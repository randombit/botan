/*
* SM4
* (C) 2017 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SM4_H_
#define BOTAN_SM4_H_

#include <botan/block_cipher.h>

namespace Botan {

/**
* SM4
*/
class SM4 final : public Block_Cipher_Fixed_Params<16, 16> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string name() const override { return "SM4"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<SM4>(); }

      std::string provider() const override;
      size_t parallelism() const override;
      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

#if defined(BOTAN_HAS_SM4_ARMV8)
      void sm4_armv8_encrypt(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void sm4_armv8_decrypt(const uint8_t in[], uint8_t out[], size_t blocks) const;
#endif

#if defined(BOTAN_HAS_SM4_GFNI)
      void sm4_gfni_encrypt(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void sm4_gfni_decrypt(const uint8_t in[], uint8_t out[], size_t blocks) const;
#endif

      secure_vector<uint32_t> m_RK;
};

}  // namespace Botan

#endif
