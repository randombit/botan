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
* Inherit and overload as desired to suit local policy concerns
*/
class BOTAN_DLL Policy
   {
   public:

      /**
      * Returns a list of ciphers we are willing to negotiate, in
      * order of preference. Allowed values: any block cipher name, or
      * ARC4.
      */
      virtual std::vector<std::string> allowed_ciphers() const;

      /**
      * Returns a list of hash algorithms we are willing to use, in
      * order of preference. This is used for both MACs and signatures.
      * Allowed values: any hash name, though currently only MD5,
      * SHA-1, and the SHA-2 variants are used.
      */
      virtual std::vector<std::string> allowed_hashes() const;

      /**
      * Returns a list of key exchange algorithms we are willing to
      * use, in order of preference. Allowed values: DH, empty string
      * (representing RSA using server certificate key)
      */
      virtual std::vector<std::string> allowed_key_exchange_methods() const;

      /**
      * Returns a list of signature algorithms we are willing to
      * use, in order of preference. Allowed values RSA and DSA.
      */
      virtual std::vector<std::string> allowed_signature_methods() const;

      /**
      * Return list of ECC curves we are willing to use in order of preference
      */
      virtual std::vector<std::string> allowed_ecc_curves() const;

      /**
      * Returns a list of signature algorithms we are willing to use,
      * in order of preference. Allowed values any value of
      * Compression_Method.
      */
      virtual std::vector<byte> compression() const;

      /**
      * Choose an elliptic curve to use
      */
      virtual std::string choose_curve(const std::vector<std::string>& curve_names) const;

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

      /**
      * If this function returns false, unknown SRP/PSK identifiers
      * will be rejected with an unknown_psk_identifier alert as soon
      * as the non-existence is identified. Otherwise, a false
      * identifier value will be used and the protocol allowed to
      * proceed, causing the login to eventually fail without
      * revealing that the username does not exist on this system.
      */
      virtual bool hide_unknown_users() const { return false; }

      /**
      * @return the minimum version that we are willing to negotiate
      */
      virtual Protocol_Version min_version() const
         { return Protocol_Version::SSL_V3; }

      /**
      * @return the version we would prefer to negotiate
      */
      virtual Protocol_Version pref_version() const
         { return Protocol_Version::TLS_V12; }

      /**
      * Return allowed ciphersuites, in order of preference
      */
      std::vector<u16bit> ciphersuite_list(bool have_srp) const;

      u16bit choose_suite(const std::vector<u16bit>& client_suites,
                          const std::vector<std::string>& available_cert_types,
                          bool have_shared_ecc_curve,
                          bool have_srp) const;

      byte choose_compression(const std::vector<byte>& client_algos) const;

      virtual ~Policy() {}
   };

}

}

#endif
