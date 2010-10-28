/*
* Luby-Rackoff
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_LUBY_RACKOFF_H__
#define BOTAN_LUBY_RACKOFF_H__

#include <botan/block_cipher.h>
#include <botan/hash.h>

namespace Botan {

/**
* Luby-Rackoff block cipher construction
*/
class BOTAN_DLL LubyRackoff : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      size_t block_size() const { return 2 * hash->output_length(); }

      Key_Length_Specification key_spec() const
         {
         return Key_Length_Specification(2, 32, 2);
         }

      void clear();
      std::string name() const;
      BlockCipher* clone() const;

      /**
      * @param hash function to use to form the block cipher
      */
      LubyRackoff(HashFunction* hash);
      ~LubyRackoff() { delete hash; }
   private:
      void key_schedule(const byte[], size_t);

      HashFunction* hash;
      SecureVector<byte> K1, K2;
   };

}

#endif
