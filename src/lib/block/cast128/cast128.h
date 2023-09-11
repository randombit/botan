/*
* CAST-128
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CAST128_H_
#define BOTAN_CAST128_H_

#include <botan/block_cipher.h>

namespace Botan {

/**
* CAST-128
*/
class CAST_128 final : public Block_Cipher_Fixed_Params<8, 11, 16> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string name() const override { return "CAST-128"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<CAST_128>(); }

      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

      static void cast_ks(secure_vector<uint32_t>& ks, secure_vector<uint32_t>& user_key);

      secure_vector<uint32_t> m_MK;
      secure_vector<uint8_t> m_RK;
};

}  // namespace Botan

#endif
