/*
* Twofish
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TWOFISH_H_
#define BOTAN_TWOFISH_H_

#include <botan/block_cipher.h>

#include <array>

namespace Botan {

/**
* Twofish, an AES finalist
*/
class Twofish final : public Block_Cipher_Fixed_Params<16, 16, 32, 8> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string name() const override { return "Twofish"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<Twofish>(); }

      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

      static const std::array<uint32_t, 256> MDS0;
      static const std::array<uint32_t, 256> MDS1;
      static const std::array<uint32_t, 256> MDS2;
      static const std::array<uint32_t, 256> MDS3;
      static const std::array<uint8_t, 256> Q0;
      static const std::array<uint8_t, 256> Q1;
      static const std::array<uint8_t, 32> RS;
      static const std::array<uint8_t, 255> EXP_TO_POLY;
      static const std::array<uint8_t, 255> POLY_TO_EXP;

      secure_vector<uint32_t> m_SB, m_RK;
};

}  // namespace Botan

#endif
