/*
* Block Cipher Cascade
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CASCADE_H__
#define BOTAN_CASCADE_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* Block Cipher Cascade
*/
class BOTAN_DLL Cascade_Cipher : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      size_t block_size() const { return block; }

      Key_Length_Specification key_spec() const
         {
         return Key_Length_Specification(cipher1->maximum_keylength() +
                                         cipher2->maximum_keylength());
         }

      void clear();
      std::string name() const;
      BlockCipher* clone() const;

      /**
      * Create a cascade of two block ciphers
      * @param cipher1 the first cipher
      * @param cipher2 the second cipher
      */
      Cascade_Cipher(BlockCipher* cipher1, BlockCipher* cipher2);

      ~Cascade_Cipher();
   private:
      void key_schedule(const byte[], size_t);

      size_t block;
      BlockCipher* cipher1;
      BlockCipher* cipher2;
   };


}

#endif
