/*
* Threefish-512
* (C) 2013,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_THREEFISH_512_H_
#define BOTAN_THREEFISH_512_H_

#include <botan/block_cipher.h>

namespace Botan {

/**
* Threefish-512
*/
class Threefish_512 final : public Block_Cipher_Fixed_Params<64, 64, 0, 1, Tweakable_Block_Cipher> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void set_tweak(const uint8_t tweak[], size_t len) override;

      void clear() override;

      std::string name() const override { return "Threefish-512"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<Threefish_512>(); }

      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

      // Interface for Skein
      friend class Skein_512;

      void skein_feedfwd(const secure_vector<uint64_t>& M, const secure_vector<uint64_t>& T);

      // Private data
      secure_vector<uint64_t> m_T;
      secure_vector<uint64_t> m_K;
};

}  // namespace Botan

#endif
