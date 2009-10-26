/*
* XTEA in SSE2
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_XTEA_SSE2_H__
#define BOTAN_XTEA_SSE2_H__

#include <botan/xtea.h>

namespace Botan {

/*
* XTEA (SSE2 variant)
*/
class BOTAN_DLL XTEA_SSE2 : public XTEA
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;
      BlockCipher* clone() const { return new XTEA_SSE2; }
   };

}

#endif
