/*
* Block Cipher Cascade
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CASCADE_H_
#define BOTAN_CASCADE_H_

#include <botan/block_cipher.h>

namespace Botan {

/**
* Block Cipher Cascade
*/
class Cascade_Cipher final : public BlockCipher {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      size_t block_size() const override { return m_block_size; }

      Key_Length_Specification key_spec() const override {
         return Key_Length_Specification(m_cipher1->maximum_keylength() + m_cipher2->maximum_keylength());
      }

      void clear() override;
      std::string name() const override;
      std::unique_ptr<BlockCipher> new_object() const override;

      bool has_keying_material() const override;

      /**
      * Create a cascade of two block ciphers
      * @param cipher1 the first cipher
      * @param cipher2 the second cipher
      */
      Cascade_Cipher(std::unique_ptr<BlockCipher> cipher1, std::unique_ptr<BlockCipher> cipher2);

      Cascade_Cipher(const Cascade_Cipher&) = delete;
      Cascade_Cipher& operator=(const Cascade_Cipher&) = delete;

   private:
      void key_schedule(std::span<const uint8_t>) override;

      std::unique_ptr<BlockCipher> m_cipher1, m_cipher2;
      size_t m_block_size;
};

}  // namespace Botan

#endif
