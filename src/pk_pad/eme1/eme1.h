/*
* EME1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_EME1_H__
#define BOTAN_EME1_H__

#include <botan/eme.h>
#include <botan/kdf.h>
#include <botan/hash.h>

namespace Botan {

/**
* EME1, aka OAEP
*/
class BOTAN_DLL EME1 : public EME
   {
   public:
      size_t maximum_input_size(size_t) const;

      /**
      * @param hash object to use for hashing (takes ownership)
      * @param P an optional label. Normally empty.
      */
      EME1(HashFunction* hash, const std::string& P = "");

      ~EME1() { delete mgf; }
   private:
      SecureVector<byte> pad(const byte[], size_t, size_t,
                             RandomNumberGenerator&) const;
      SecureVector<byte> unpad(const byte[], size_t, size_t) const;

      SecureVector<byte> Phash;
      MGF* mgf;
   };

}

#endif
