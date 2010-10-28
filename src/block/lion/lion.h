/*
* Lion
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_LION_H__
#define BOTAN_LION_H__

#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/hash.h>

namespace Botan {

/**
* Lion is a block cipher construction designed by Ross Anderson and
* Eli Biham, described in "Two Practical and Provably Secure Block
* Ciphers: BEAR and LION". It has a variable block size and is
* designed to encrypt very large blocks (up to a megabyte)

* http://www.cl.cam.ac.uk/~rja14/Papers/bear-lion.pdf
*/
class BOTAN_DLL Lion : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      size_t block_size() const { return BLOCK_SIZE; }

      Key_Length_Specification key_spec() const
         {
         return Key_Length_Specification(2, 2*hash->output_length(), 2);
         }

      void clear();
      std::string name() const;
      BlockCipher* clone() const;

      /**
      * @param hash the hash to use internally
      * @param cipher the stream cipher to use internally
      * @param block_size the size of the block to use
      */
      Lion(HashFunction* hash,
           StreamCipher* cipher,
           size_t block_size);

      ~Lion() { delete hash; delete cipher; }
   private:
      void key_schedule(const byte[], size_t);

      const size_t BLOCK_SIZE, LEFT_SIZE, RIGHT_SIZE;

      HashFunction* hash;
      StreamCipher* cipher;
      SecureVector<byte> key1, key2;
   };

}

#endif
