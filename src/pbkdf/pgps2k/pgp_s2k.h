/*
* OpenPGP PBKDF
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_OPENPGP_S2K_H__
#define BOTAN_OPENPGP_S2K_H__

#include <botan/pbkdf.h>
#include <botan/hash.h>

namespace Botan {

/**
* OpenPGP's S2K
*/
class BOTAN_DLL OpenPGP_S2K : public PBKDF
   {
   public:
      /**
      * @param hash_in the hash function to use
      */
      OpenPGP_S2K(HashFunction* hash_in) : hash(hash_in) {}

      ~OpenPGP_S2K() { delete hash; }

      std::string name() const
         {
         return "OpenPGP-S2K(" + hash->name() + ")";
         }

      PBKDF* clone() const
         {
         return new OpenPGP_S2K(hash->clone());
         }

      OctetString derive_key(u32bit output_len,
                             const std::string& passphrase,
                             const byte salt[], u32bit salt_len,
                             u32bit iterations) const;
   private:
      HashFunction* hash;
   };

}

#endif
