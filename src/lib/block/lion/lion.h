/*
* Lion
* (C) 1999-2007,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_LION_H_
#define BOTAN_LION_H_

#include <botan/block_cipher.h>
#include <botan/hash.h>
#include <botan/stream_cipher.h>

namespace Botan {

/**
* Lion is a block cipher construction designed by Ross Anderson and
* Eli Biham, described in "Two Practical and Provably Secure Block
* Ciphers: BEAR and LION". It has a variable block size and is
* designed to encrypt very large blocks (up to a megabyte)

* https://www.cl.cam.ac.uk/~rja14/Papers/bear-lion.pdf
*/
class Lion final : public BlockCipher {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      size_t block_size() const override { return m_block_size; }

      Key_Length_Specification key_spec() const override {
         return Key_Length_Specification(2, 2 * m_hash->output_length(), 2);
      }

      void clear() override;
      std::string name() const override;
      std::unique_ptr<BlockCipher> new_object() const override;
      bool has_keying_material() const override;

      /**
      * @param hash the hash to use internally
      * @param cipher the stream cipher to use internally
      * @param block_size the size of the block to use
      */
      Lion(std::unique_ptr<HashFunction> hash, std::unique_ptr<StreamCipher> cipher, size_t block_size);

   private:
      void key_schedule(std::span<const uint8_t> key) override;

      size_t left_size() const { return m_hash->output_length(); }

      size_t right_size() const { return m_block_size - left_size(); }

      const size_t m_block_size;
      std::unique_ptr<HashFunction> m_hash;
      std::unique_ptr<StreamCipher> m_cipher;
      secure_vector<uint8_t> m_key1, m_key2;
};

}  // namespace Botan

#endif
