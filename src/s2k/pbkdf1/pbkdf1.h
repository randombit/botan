/*
* PBKDF1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PBKDF1_H__
#define BOTAN_PBKDF1_H__

#include <botan/s2k.h>
#include <botan/hash.h>

namespace Botan {

/**
* This class implements the PKCS #5 PBKDF1 functionality.
*/
class BOTAN_DLL PKCS5_PBKDF1 : public S2K
   {
   public:
      std::string name() const;
      S2K* clone() const;

      OctetString derive_key(u32bit output_len,
                             const std::string& passphrase,
                             const byte salt[], u32bit salt_len,
                             u32bit iterations) const;

      /**
      * Create a PKCS #5 instance using the specified hash function.
      * @param hash_in pointer to a hash function object to use
      */
      PKCS5_PBKDF1(HashFunction* hash_in) : hash(hash_in) {}

      /**
      * Copy constructor
      * @param other the object to copy
      */
      PKCS5_PBKDF1(const PKCS5_PBKDF1& other) :
         S2K(), hash(other.hash->clone()) {}

      ~PKCS5_PBKDF1() { delete hash; }
   private:
      HashFunction* hash;
   };

}

#endif
