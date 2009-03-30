/*
* Salsa20
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SALSA20_H__
#define BOTAN_SALSA20_H__

#include <botan/stream_cipher.h>

namespace Botan {

/*
* Salsa20
*/
class BOTAN_DLL Salsa20 : public StreamCipher
   {
   public:
      void clear() throw();
      std::string name() const;
      StreamCipher* clone() const { return new Salsa20; }

      void resync(const byte[], u32bit);

      Salsa20();
      ~Salsa20() { clear(); }
   private:
      void cipher(const byte[], byte[], u32bit);
      void key_schedule(const byte[], u32bit);

      SecureBuffer<u32bit, 16> state;

      SecureBuffer<byte, 64> buffer;
      u32bit position;
   };

}

#endif
