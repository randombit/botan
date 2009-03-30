/*
* KDF1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_KDF1_H__
#define BOTAN_KDF1_H__

#include <botan/kdf.h>
#include <botan/hash.h>

namespace Botan {

/*
* KDF1
*/
class BOTAN_DLL KDF1 : public KDF
   {
   public:
      SecureVector<byte> derive(u32bit,
                                const byte secret[], u32bit secret_len,
                                const byte P[], u32bit P_len) const;

      KDF1(HashFunction* h) : hash(h) {}
      KDF1(const KDF1& other) : KDF(), hash(other.hash->clone()) {}

      ~KDF1() { delete hash; }
   private:
      HashFunction* hash;
   };

}

#endif
