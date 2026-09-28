/*
* Twofish
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TWOFISH_H_
#define BOTAN_TWOFISH_H_

#include <botan/block_cipher.h>
#include <botan/secmem.h>

namespace Botan {

/**
* Twofish, an AES finalist
*/
class Twofish final : public Block_Cipher_Fixed_Params<16, 16, 32, 8> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;
      std::string provider() const override;

      std::string name() const override { return "Twofish"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<Twofish>(); }

      size_t parallelism() const override;

      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

#if defined(BOTAN_HAS_TWOFISH_AVX512)
      void avx512_encrypt(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void avx512_decrypt(const uint8_t in[], uint8_t out[], size_t blocks) const;
#endif

      secure_vector<uint32_t> m_SB;
      secure_vector<uint32_t> m_RK;

      secure_vector<uint8_t> m_QS;  // Sboxes without MDS applied, only used for AVX-512
};

}  // namespace Botan

#endif
