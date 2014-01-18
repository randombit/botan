/*
* Luby-Rackoff
* (C) 1999-2008,2014 Jack Lloyd
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
      void encrypt_n(const byte in[], byte out[], size_t blocks) const override;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const override;

      size_t block_size() const override { return 2 * m_hash->output_length(); }

      Key_Length_Specification key_spec() const override
         {
         return Key_Length_Specification(2, 32, 2);
         }

      void clear() override;
      std::string name() const override;
      BlockCipher* clone() const override;

      /**
      * @param hash function to use to form the block cipher
      */
      LubyRackoff(HashFunction* hash) : m_hash(hash) {}

   private:
      void key_schedule(const byte[], size_t) override;

      std::unique_ptr<HashFunction> m_hash;
      secure_vector<byte> m_K1, m_K2;
   };

}

#endif
