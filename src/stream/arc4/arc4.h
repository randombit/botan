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

/**
* Alleged RC4
*/
class BOTAN_DLL ARC4 : public StreamCipher
   {
   public:
      void cipher(const byte in[], byte out[], size_t length);

      void clear();
      std::string name() const;

      StreamCipher* clone() const { return new ARC4(SKIP); }

      Key_Length_Specification key_spec() const
         {
         return Key_Length_Specification(1, 256);
         }

      /**
      * @param skip skip this many initial bytes in the keystream
      */
      ARC4(size_t skip = 0);

      ~ARC4() { clear(); }
   private:
      void key_schedule(const byte[], size_t);
      void generate();

      const size_t SKIP;

      byte X, Y;
      SecureVector<byte> state;

      SecureVector<byte> buffer;
      size_t position;
   };

}

#endif
