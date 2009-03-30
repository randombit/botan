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

/*
* Lion
*/
class BOTAN_DLL Lion : public BlockCipher
   {
   public:
      void clear() throw();
      std::string name() const;
      BlockCipher* clone() const;

      Lion(HashFunction*, StreamCipher*, u32bit);
      ~Lion() { delete hash; delete cipher; }
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);

      const u32bit LEFT_SIZE, RIGHT_SIZE;

      HashFunction* hash;
      StreamCipher* cipher;
      SecureVector<byte> key1, key2;
   };

}

#endif
