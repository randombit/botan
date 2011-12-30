/*
* TLS Cipher Suites
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_CIPHER_SUITES_H__
#define BOTAN_TLS_CIPHER_SUITES_H__

#include <botan/types.h>
#include <botan/tls_magic.h>
#include <string>

namespace Botan {

/**
* Ciphersuite Information
*/
class BOTAN_DLL TLS_Cipher_Suite
   {
   public:
      static TLS_Ciphersuite_Algos lookup_ciphersuite(u16bit suite);

      std::string cipher_algo() const { return cipher; }
      std::string mac_algo() const { return mac; }

      size_t cipher_keylen() const { return cipher_key_length; }

      TLS_Ciphersuite_Algos kex_type() const { return kex_algo; }
      TLS_Ciphersuite_Algos sig_type() const { return sig_algo; }

      TLS_Cipher_Suite(u16bit ciphersuite_code = 0);
   private:
      TLS_Ciphersuite_Algos kex_algo, sig_algo;
      std::string cipher, mac;
      size_t cipher_key_length;
   };

}

#endif
