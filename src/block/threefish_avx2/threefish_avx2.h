/*
* Threefish-512 in AVX2
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_THREEFISH_AVX2_H__
#define BOTAN_THREEFISH_AVX2_H__

#include <botan/threefish.h>

namespace Botan {

/**
* Threefish-512
*/
class BOTAN_DLL Threefish_512_AVX2 : public Threefish_512
   {
   private:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const override;
      BlockCipher* clone() const override { return new Threefish_512_AVX2; }
   };

}

#endif
