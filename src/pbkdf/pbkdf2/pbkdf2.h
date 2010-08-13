/*
* PBKDF2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PBKDF2_H__
#define BOTAN_PBKDF2_H__

#include <botan/pbkdf.h>
#include <botan/mac.h>

namespace Botan {

/**
* PKCS #5 PBKDF2
*/
class BOTAN_DLL PKCS5_PBKDF2 : public PBKDF
   {
   public:
      std::string name() const
         {
         return "PBKDF2(" + mac->name() + ")";
         }

      PBKDF* clone() const
         {
         return new PKCS5_PBKDF2(mac->clone());
         }

      OctetString derive_key(u32bit output_len,
                             const std::string& passphrase,
                             const byte salt[], u32bit salt_len,
                             u32bit iterations) const;

      /**
      * Create a PKCS #5 instance using the specified message auth code
      * @param mac_fn the MAC to use
      */
      PKCS5_PBKDF2(MessageAuthenticationCode* mac_fn) : mac(mac_fn) {}

      /**
      * Destructor
      */
      ~PKCS5_PBKDF2() { delete mac; }
   private:
      MessageAuthenticationCode* mac;
   };

}

#endif
