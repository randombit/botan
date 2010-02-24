/*
* PBKDF2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PBKDF2_H__
#define BOTAN_PBKDF2_H__

#include <botan/s2k.h>
#include <botan/mac.h>

namespace Botan {

/**
* This class implements the PKCS #5 PBKDF2 functionality.
*/
class BOTAN_DLL PKCS5_PBKDF2 : public S2K
   {
   public:
      std::string name() const;
      S2K* clone() const;

      OctetString derive_key(u32bit output_len,
                             const std::string& passphrase,
                             const byte salt[], u32bit salt_len,
                             u32bit iterations) const;

      /**
      * Create a PKCS #5 instance using the specified message auth code
      * @param mac the MAC to use
      */
      PKCS5_PBKDF2(MessageAuthenticationCode* mac);
      ~PKCS5_PBKDF2();
   private:
      MessageAuthenticationCode* mac;
   };

}

#endif
