/*
* ARC4
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ARC4_H__
#define BOTAN_ARC4_H__

#include <botan/stream_cipher.h>
#include <botan/types.h>

namespace Botan {

/*
* ARC4
*/
class BOTAN_DLL ARC4 : public StreamCipher
   {
   public:
      void clear() throw();
      std::string name() const;
      StreamCipher* clone() const { return new ARC4(SKIP); }
      ARC4(u32bit = 0);
      ~ARC4() { clear(); }
   private:
      void cipher(const byte[], byte[], u32bit);
      void key_schedule(const byte[], u32bit);
      void generate();

      const u32bit SKIP;

      SecureBuffer<byte, DEFAULT_BUFFERSIZE> buffer;
      SecureBuffer<u32bit, 256> state;
      u32bit X, Y, position;
   };

}

#endif
