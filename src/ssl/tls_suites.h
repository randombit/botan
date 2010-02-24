/**
* Cipher Suites 
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_CIPHERSUITES_H__
#define BOTAN_TLS_CIPHERSUITES_H__

#include <botan/types.h>
#include <string>

namespace Botan {

/**
* Ciphersuite Information
*/
class BOTAN_DLL CipherSuite
   {
   public:
      enum Kex_Type { NO_KEX, RSA_KEX, DH_KEX };
      enum Sig_Type { NO_SIG, RSA_SIG, DSA_SIG };

      std::string cipher_algo() const { return cipher; }
      std::string mac_algo() const { return mac; }

      u32bit cipher_keylen() const { return cipher_key_length; }
      Kex_Type kex_type() const { return kex_algo; }
      Sig_Type sig_type() const { return sig_algo; }

      CipherSuite(u16bit = 0);
   private:
      Kex_Type kex_algo;
      Sig_Type sig_algo;
      std::string cipher, mac;
      u32bit cipher_key_length;
   };

}

#endif
