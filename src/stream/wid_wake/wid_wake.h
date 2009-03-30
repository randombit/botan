/*
* WiderWake
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_WIDER_WAKE_H__
#define BOTAN_WIDER_WAKE_H__

#include <botan/stream_cipher.h>

namespace Botan {

/*
* WiderWake4+1-BE
*/
class BOTAN_DLL WiderWake_41_BE : public StreamCipher
   {
   public:
      void clear() throw();
      std::string name() const { return "WiderWake4+1-BE"; }
      StreamCipher* clone() const { return new WiderWake_41_BE; }
      WiderWake_41_BE() : StreamCipher(16, 16, 1, 8) {}
   private:
      void cipher(const byte[], byte[], u32bit);
      void key_schedule(const byte[], u32bit);
      void resync(const byte[], u32bit);

      void generate(u32bit);

      SecureBuffer<byte, DEFAULT_BUFFERSIZE> buffer;
      SecureBuffer<u32bit, 256> T;
      SecureBuffer<u32bit, 5> state;
      SecureBuffer<u32bit, 4> t_key;
      u32bit position;
   };

}

#endif
