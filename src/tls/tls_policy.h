/*
* Policies
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_POLICY_H__
#define BOTAN_TLS_POLICY_H__

#include <botan/tls_version.h>
#include <botan/x509cert.h>
#include <botan/dl_group.h>
#include <vector>

namespace Botan {

namespace TLS {

/**
* TLS Policy Base Class
* Inherit and overload as desired to suite local policy concerns
*/
class BOTAN_DLL Policy
   {
   public:
      /*
      * Return allowed ciphersuites, in order of preference
      */
      std::vector<u16bit> ciphersuite_list(bool have_srp) const;

      u16bit choose_suite(const std::vector<u16bit>& client_suites,
                          bool have_rsa,
                          bool have_dsa,
                          bool have_srp) const;

      byte choose_compression(const std::vector<byte>& client_algos) const;

      std::vector<std::string> allowed_ciphers() const;

      std::vector<std::string> allowed_hashes() const;

      std::vector<std::string> allowed_key_exchange_methods() const;

      std::vector<std::string> allowed_signature_methods() const;

      virtual std::vector<byte> compression() const;

      /**
      * Require support for RFC 5746 extensions to enable
      * renegotiation.
      *
      * @warning Changing this to false exposes you to injected
      * plaintext attacks. Read the RFC for background.
      */
      virtual bool require_secure_renegotiation() const { return true; }

      /**
      * Return the group to use for ephemeral Diffie-Hellman key agreement
      */
      virtual DL_Group dh_group() const { return DL_Group("modp/ietf/1536"); }

      /*
      * @return the minimum version that we are willing to negotiate
      */
      virtual Protocol_Version min_version() const
         { return Protocol_Version::SSL_V3; }

      /*
      * @return the version we would prefer to negotiate
      */
      virtual Protocol_Version pref_version() const
         { return Protocol_Version::TLS_V12; }

      virtual ~Policy() {}
   };

}

}

#endif
