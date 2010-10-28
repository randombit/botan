/*
* Cipher Suites
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_CIPHERSUITES_H__
#define BOTAN_TLS_CIPHERSUITES_H__

#include <botan/types.h>
#include <botan/tls_magic.h>
#include <string>

namespace Botan {

/**
* Ciphersuite Information
*/
class BOTAN_DLL CipherSuite
   {
   public:
      static TLS_Ciphersuite_Algos lookup_ciphersuite(u16bit suite);

      std::string cipher_algo() const { return cipher; }
      std::string mac_algo() const { return mac; }

      size_t cipher_keylen() const { return cipher_key_length; }

      TLS_Ciphersuite_Algos kex_type() const { return kex_algo; }
      TLS_Ciphersuite_Algos sig_type() const { return sig_algo; }

      CipherSuite(u16bit = 0);
   private:
      TLS_Ciphersuite_Algos kex_algo, sig_algo;
      std::string cipher, mac;
      size_t cipher_key_length;
   };

}

#endif
