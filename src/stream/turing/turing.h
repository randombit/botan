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

/**
* Turing
*/
class BOTAN_DLL Turing : public StreamCipher
   {
   public:
      void cipher(const byte in[], byte out[], size_t length);
      void set_iv(const byte iv[], size_t iv_length);

      bool valid_iv_length(size_t iv_len) const
         { return (iv_len % 4 == 0 && iv_len <= 16); }

      Key_Length_Specification key_spec() const
         {
         return Key_Length_Specification(4, 32, 4);
         }

      void clear();
      std::string name() const { return "Turing"; }
      StreamCipher* clone() const { return new Turing; }

   private:
      void key_schedule(const byte[], size_t);
      void generate();

      static u32bit fixedS(u32bit);

      static const u32bit Q_BOX[256];
      static const byte SBOX[256];

      secure_vector<u32bit> S0, S1, S2, S3;
      secure_vector<u32bit> R;
      secure_vector<u32bit> K;
      secure_vector<byte> buffer;
      size_t position;
   };

}

#endif
