/*
* Serpent
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SERPENT_H__
#define BOTAN_SERPENT_H__

#include <botan/block_cipher.h>

namespace Botan {

/*
* Serpent
*/
class BOTAN_DLL Serpent : public BlockCipher
   {
   public:
      void clear() throw() { round_key.clear(); }
      std::string name() const { return "Serpent"; }
      BlockCipher* clone() const { return new Serpent; }
      Serpent() : BlockCipher(16, 16, 32, 8) {}
   protected:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);

      SecureBuffer<u32bit, 132> round_key;
   };

}

#endif
