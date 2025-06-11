/*
* Kuznyechik
* (C) 2023 Richard Huveneers
*     2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_KUZNYECHIK_H_
#define BOTAN_KUZNYECHIK_H_

#include <botan/block_cipher.h>
#include <botan/secmem.h>

namespace Botan {

/**
* Kuznyechik
*/
class Kuznyechik final : public Botan::Block_Cipher_Fixed_Params<16, 32> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string name() const override { return "Kuznyechik"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<Kuznyechik>(); }

      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;
      secure_vector<uint64_t> m_rke;
      secure_vector<uint64_t> m_rkd;
};

}  // namespace Botan

#endif
