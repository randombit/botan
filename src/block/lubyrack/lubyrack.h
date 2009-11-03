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

/*
* Luby-Rackoff
*/
class BOTAN_DLL LubyRackoff : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear();
      std::string name() const;
      BlockCipher* clone() const;

      LubyRackoff(HashFunction* hash);
      ~LubyRackoff() { delete hash; }
   private:
      void key_schedule(const byte[], u32bit);

      HashFunction* hash;
      SecureVector<byte> K1, K2;
   };

}

#endif
