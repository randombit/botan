/*
* TLS Cipher Suites
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_CIPHER_SUITES_H__
#define BOTAN_TLS_CIPHER_SUITES_H__

#include <botan/types.h>
#include <string>

namespace Botan {

namespace TLS {

/**
* Ciphersuite Information
*/
class BOTAN_DLL Ciphersuite
   {
   public:
      static Ciphersuite lookup_ciphersuite(u16bit suite);

      /**
      * Formats the ciphersuite back to an RFC-style ciphersuite string
      */
      std::string to_string() const;

      std::string kex_algo() const { return m_kex_algo; }
      std::string sig_algo() const { return m_sig_algo; }

      std::string cipher_algo() const { return m_cipher_algo; }
      std::string mac_algo() const { return m_mac_algo; }

      size_t cipher_keylen() const { return m_cipher_keylen; }

      bool valid() const { return (m_cipher_keylen > 0); }

      Ciphersuite() : m_cipher_keylen(0) {}

      Ciphersuite(const std::string& sig_algo,
                  const std::string& kex_algo,
                  const std::string& mac_algo,
                  const std::string& cipher_algo,
                  size_t cipher_algo_keylen);
   private:
      std::string m_sig_algo, m_kex_algo, m_mac_algo, m_cipher_algo;
      size_t m_cipher_keylen;
   };

}

}

#endif
