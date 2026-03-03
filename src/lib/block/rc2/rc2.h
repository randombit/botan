/*
* RC2 Block Cipher
* (C) 2026 Botan Project
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_RC2_H_
#define BOTAN_RC2_H_

#include <botan/block_cipher.h>
#include <botan/secmem.h>

namespace Botan {

/**
* RC2 Block Cipher
*
* A 64-bit block cipher designed by Ron Rivest in 1987.
* This implementation supports effective key bits parameter used
* in PKCS#12 for export-restricted variants (40-bit, 128-bit).
*
* WARNING: RC2 is considered cryptographically weak and should
* only be used for legacy compatibility (e.g., parsing old PKCS#12 files).
*/
class RC2 final : public Block_Cipher_Fixed_Params<8, 1, 128> {
   public:
      /**
       * @param effective_key_bits the effective key strength (1-1024, typically 40 or 128)
       *        This limits the actual key strength for export compliance.
       *        Default is 1024 (no limitation).
       */
      explicit RC2(size_t effective_key_bits = 1024);

      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string name() const override;

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<RC2>(m_effective_key_bits); }

      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

      size_t m_effective_key_bits;
      secure_vector<uint16_t> m_K;  // 64 expanded key words
};

}  // namespace Botan

#endif
