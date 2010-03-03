/*
* Salsa20 / XSalsa20
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SALSA20_H__
#define BOTAN_SALSA20_H__

#include <botan/stream_cipher.h>

namespace Botan {

/*
* Salsa20 (and XSalsa20)
*/
class BOTAN_DLL Salsa20 : public StreamCipher
   {
   public:
      void cipher(const byte in[], byte out[], u32bit length);

      void set_iv(const byte iv[], u32bit iv_len);

      bool valid_iv_length(u32bit iv_len) const
         { return (iv_len == 8 || iv_len == 24); }

      void clear();
      std::string name() const;
      StreamCipher* clone() const { return new Salsa20; }

      Salsa20();
      ~Salsa20() { clear(); }
   private:
      void key_schedule(const byte key[], u32bit key_len);

      SecureBuffer<u32bit, 16> state;

      SecureBuffer<byte, 64> buffer;
      u32bit position;
   };

}

#endif
