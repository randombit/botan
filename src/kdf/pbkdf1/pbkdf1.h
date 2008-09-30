/*************************************************
* PBKDF1 Header File                             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_PBKDF1_H__
#define BOTAN_PBKDF1_H__

#include <botan/s2k.h>
#include <botan/base.h>

namespace Botan {

/*************************************************
* PKCS #5 PBKDF1                                 *
*************************************************/
class BOTAN_DLL PKCS5_PBKDF1 : public S2K
   {
   public:
      std::string name() const;
      S2K* clone() const;

      PKCS5_PBKDF1(HashFunction* hash_in) : hash(hash_in) {}
      PKCS5_PBKDF1(const PKCS5_PBKDF1& other) : hash(other.hash->clone()) {}
      ~PKCS5_PBKDF1() { delete hash; }
   private:
      OctetString derive(u32bit, const std::string&,
                          const byte[], u32bit, u32bit) const;

      HashFunction* hash;
   };

}

#endif
