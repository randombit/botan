/*
* XTEA in SIMD
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_XTEA_SIMD_H__
#define BOTAN_XTEA_SIMD_H__

#include <botan/xtea.h>

namespace Botan {

/*
* XTEA (SIMD variant)
*/
class BOTAN_DLL XTEA_SIMD : public XTEA
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;
      BlockCipher* clone() const { return new XTEA_SIMD; }
   };

}

#endif
