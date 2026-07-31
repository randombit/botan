/*
* TLS Cipher Suite
* (C) 2004-2010,2012,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_ciphersuite.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <algorithm>

namespace Botan::TLS {

size_t Ciphersuite::nonce_bytes_from_handshake() const {
   switch(m_nonce_format) {
      case Nonce_Format::CBC_MODE:
         return 0;
      case Nonce_Format::AEAD_IMPLICIT_4:
         return 4;
      case Nonce_Format::AEAD_XOR_12:
         return 12;
      case Nonce_Format::NULL_CIPHER:
         return 0;
   }

   throw Invalid_State("In Ciphersuite::nonce_bytes_from_handshake invalid enum value");
}

size_t Ciphersuite::nonce_bytes_from_record(Protocol_Version version) const {
   BOTAN_UNUSED(version);
   switch(m_nonce_format) {
      case Nonce_Format::CBC_MODE:
         return cipher_algo() == "3DES" ? 8 : 16;
      case Nonce_Format::AEAD_IMPLICIT_4:
         return 8;
      case Nonce_Format::AEAD_XOR_12:
      case Nonce_Format::NULL_CIPHER:
         return 0;
   }

   throw Invalid_State("In Ciphersuite::nonce_bytes_from_handshake invalid enum value");
}

bool Ciphersuite::is_scsv(uint16_t suite) {
   // Both signaling cipher suite values - skip them when iterating
   // negotiable ciphersuites. The two callers are:
   //
   // - 0x00FF: TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746). Consumed by
   //   Client_Hello_12::Client_Hello_12 to set secure_renegotiation when
   //   the renegotiation_info extension is absent.
   //
   // - 0x5600: TLS_FALLBACK_SCSV (RFC 7507). Recognized so it is filtered
   //   out of negotiation, but the inappropriate_fallback enforcement is
   //   intentionally not implemented:
   //     * Botan does not support TLS 1.0 / 1.1, so the 1.2 -> 1.0/1.1
   //       fallback that SCSV was originally designed to detect cannot
   //       occur here.
   //     * The 1.3 -> 1.2 downgrade is already protected by the
   //       ServerHello.random sentinel (RFC 8446 4.1.3, DOWNGRADE_TLS12),
   //       which Botan's TLS 1.3 client enforces at
   //       tls_client_impl_13.cpp via random_signals_downgrade().
   //
   // TODO: derive from IANA file in script
   return (suite == 0x00FF || suite == 0x5600);
}

bool Ciphersuite::psk_ciphersuite() const {
   return kex_method() == Kex_Algo::PSK || kex_method() == Kex_Algo::ECDHE_PSK;
}

bool Ciphersuite::ecc_ciphersuite() const {
   return kex_method() == Kex_Algo::ECDH || kex_method() == Kex_Algo::ECDHE_PSK || auth_method() == Auth_Method::ECDSA;
}

bool Ciphersuite::usable_in_version(Protocol_Version version) const {
   // RFC 8446 B.4.:
   //   Although TLS 1.3 uses the same cipher suite space as previous
   //   versions of TLS, TLS 1.3 cipher suites are defined differently, only
   //   specifying the symmetric ciphers, and cannot be used for TLS 1.2.
   //   Similarly, cipher suites for TLS 1.2 and lower cannot be used with
   //   TLS 1.3.
   //
   // Currently cipher suite codes {0x13,0x01} through {0x13,0x05} are
   // allowed for TLS 1.3. This may change in the future.
   const auto is_legacy_suite = (ciphersuite_code() & 0xFF00) != 0x1300;
   return version.is_pre_tls_13() == is_legacy_suite;
}

bool Ciphersuite::cbc_ciphersuite() const {
   return (mac_algo() != "AEAD" && cipher_algo() != "NULL");
}

bool Ciphersuite::null_ciphersuite() const {
   return (cipher_algo() == "NULL");
}

bool Ciphersuite::aead_ciphersuite() const {
   return (mac_algo() == "AEAD");
}

bool Ciphersuite::uses_short_authentication_tag() const {
   // The only AEAD we currently support that has a short tag is CCM-8
   return cipher_algo().ends_with("/CCM(8)");
}

bool Ciphersuite::signature_used() const {
   return auth_method() != Auth_Method::IMPLICIT;
}

bool Ciphersuite::is_certificate_required() const {
   return signature_used() || kex_method() == Kex_Algo::STATIC_RSA;
}

std::optional<Ciphersuite> Ciphersuite::by_id(uint16_t suite) {
   const std::vector<Ciphersuite>& all_suites = all_known_ciphersuites();
   auto s = std::lower_bound(all_suites.begin(), all_suites.end(), suite);

   if(s != all_suites.end() && s->ciphersuite_code() == suite) {
      return *s;
   }

   return std::nullopt;  // some unknown ciphersuite
}

std::optional<Ciphersuite> Ciphersuite::from_name(std::string_view name) {
   const std::vector<Ciphersuite>& all_suites = all_known_ciphersuites();

   for(const auto& suite : all_suites) {
      if(suite.to_string() == name) {
         return suite;
      }
   }

   return std::nullopt;  // some unknown ciphersuite
}

}  // namespace Botan::TLS
