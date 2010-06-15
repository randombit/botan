/*
* OpenPGP S2K
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_OPENPGP_S2K_H__
#define BOTAN_OPENPGP_S2K_H__

#include <botan/s2k.h>
#include <botan/hash.h>

namespace Botan {

/**
* OpenPGP's S2K
*/
class BOTAN_DLL OpenPGP_S2K : public S2K
   {
   public:
      std::string name() const;
      S2K* clone() const;

      OctetString derive_key(u32bit output_len,
                             const std::string& passphrase,
                             const byte salt[], u32bit salt_len,
                             u32bit iterations) const;

      OpenPGP_S2K(HashFunction* hash_in) : hash(hash_in) {}
      ~OpenPGP_S2K() { delete hash; }
   private:
      HashFunction* hash;
   };

}

#endif
