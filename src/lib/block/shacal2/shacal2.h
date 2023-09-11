/*
* SHACAL-2
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SHACAL2_H_
#define BOTAN_SHACAL2_H_

#include <botan/block_cipher.h>

namespace Botan {

/**
* SHACAL2
*/
class SHACAL2 final : public Block_Cipher_Fixed_Params<32, 16, 64, 4> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      std::string provider() const override;
      void clear() override;

      std::string name() const override { return "SHACAL2"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<SHACAL2>(); }

      size_t parallelism() const override;
      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

#if defined(BOTAN_HAS_SHACAL2_SIMD)
      void simd_encrypt_4(const uint8_t in[], uint8_t out[]) const;
      void simd_decrypt_4(const uint8_t in[], uint8_t out[]) const;
#endif

#if defined(BOTAN_HAS_SHACAL2_AVX2)
      void avx2_encrypt_8(const uint8_t in[], uint8_t out[]) const;
      void avx2_decrypt_8(const uint8_t in[], uint8_t out[]) const;
#endif

#if defined(BOTAN_HAS_SHACAL2_X86)
      void x86_encrypt_blocks(const uint8_t in[], uint8_t out[], size_t blocks) const;
#endif

#if defined(BOTAN_HAS_SHACAL2_ARMV8)
      void armv8_encrypt_blocks(const uint8_t in[], uint8_t out[], size_t blocks) const;
#endif

      secure_vector<uint32_t> m_RK;
};

}  // namespace Botan

#endif
