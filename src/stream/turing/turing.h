/*
* Turing
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_TURING_H__
#define BOTAN_TURING_H__

#include <botan/stream_cipher.h>

namespace Botan {

/*
* Turing
*/
class BOTAN_DLL Turing : public StreamCipher
   {
   public:
      void cipher(const byte in[], byte out[], u32bit length);
      void set_iv(const byte iv[], u32bit iv_length);

      bool valid_iv_length(u32bit iv_len) const
         { return (iv_len % 4 == 0 && iv_len <= 16); }

      void clear();
      std::string name() const { return "Turing"; }
      StreamCipher* clone() const { return new Turing; }
      Turing() : StreamCipher(4, 32, 4) { position = 0; }
   private:
      void key_schedule(const byte[], u32bit);
      void generate();

      static u32bit fixedS(u32bit);

      static const u32bit Q_BOX[256];
      static const byte SBOX[256];

      SecureVector<u32bit, 256> S0, S1, S2, S3;
      SecureVector<u32bit, 17> R;
      SecureVector<u32bit> K;
      SecureVector<byte, 340> buffer;
      u32bit position;
   };

}

#endif
