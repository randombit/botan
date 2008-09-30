/*************************************************
* KDF1 Header File                                *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_KDF1_H__
#define BOTAN_KDF1_H__

#include <botan/kdf.h>
#include <botan/base.h>

namespace Botan {

/*************************************************
* KDF1                                           *
*************************************************/
class BOTAN_DLL KDF1 : public KDF
   {
   public:
      SecureVector<byte> derive(u32bit,
                                const byte secret[], u32bit secret_len,
                                const byte P[], u32bit P_len) const;

      KDF1(HashFunction* h) : hash(h) {}
      KDF1(const KDF1& other) : hash(other.hash->clone()) {}

      ~KDF1() { delete hash; }
   private:
      HashFunction* hash;
   };

}

#endif
