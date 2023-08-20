/*
* Kuznyechik
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_KUZNYECHIK_H_
#define BOTAN_KUZNYECHIK_H_

#include <botan/block_cipher.h>

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
      ~Kuznyechik() override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;
      uint64_t m_rke[10][2];
      uint64_t m_rkd[10][2];
      bool m_has_keying_material;
};

}  // namespace Botan

#endif
