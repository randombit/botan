/*
* DES
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DES_H_
#define BOTAN_DES_H_

#include <botan/block_cipher.h>

namespace Botan {

/**
* DES
*/
class DES final : public Block_Cipher_Fixed_Params<8, 8> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string name() const override { return "DES"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<DES>(); }

      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t>) override;

      secure_vector<uint32_t> m_round_key;
};

/**
* Triple DES
*/
class TripleDES final : public Block_Cipher_Fixed_Params<8, 16, 24, 8> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string name() const override { return "TripleDES"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<TripleDES>(); }

      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t>) override;

      secure_vector<uint32_t> m_round_key;
};

}  // namespace Botan

#endif
