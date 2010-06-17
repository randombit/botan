/*
* RC2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_RC2_H__
#define BOTAN_RC2_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* RC2
*/
class BOTAN_DLL RC2 : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      /**
      * Return the code of the effective key bits
      * @param bits key length
      * @return EKB code
      */
      static byte EKB_code(u32bit bits);

      void clear() { K.clear(); }
      std::string name() const { return "RC2"; }
      BlockCipher* clone() const { return new RC2; }

      RC2() : BlockCipher(8, 1, 32) {}
   private:
      void key_schedule(const byte[], u32bit);

      SecureVector<u16bit, 64> K;
   };

}

#endif
