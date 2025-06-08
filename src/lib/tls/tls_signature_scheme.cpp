/*
* (C) 2022,2023 Jack Lloyd
* (C) 2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_signature_scheme.h>

#include <botan/der_enc.h>
#include <botan/ec_group.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/pss_params.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_version.h>
#include <botan/internal/stl_util.h>

namespace Botan::TLS {

const std::vector<Signature_Scheme>& Signature_Scheme::all_available_schemes() {
   /*
   * This is ordered in some approximate order of preference
   */
   static const std::vector<Signature_Scheme> all_schemes = {

      // EdDSA 25519 is currently not supported as a signature scheme for certificates
      // certificate authentication.
      // See: https://github.com/randombit/botan/pull/2958#discussion_r851294715
      //
      // #if defined(BOTAN_HAS_ED25519)
      //       EDDSA_25519,
      // #endif

      RSA_PSS_SHA384,
      RSA_PSS_SHA256,
      RSA_PSS_SHA512,

      RSA_PKCS1_SHA384,
      RSA_PKCS1_SHA512,
      RSA_PKCS1_SHA256,

      ECDSA_SHA384,
      ECDSA_SHA512,
      ECDSA_SHA256,
   };

   return all_schemes;
}

Signature_Scheme::Signature_Scheme() : m_code(NONE) {}

Signature_Scheme::Signature_Scheme(uint16_t wire_code) : Signature_Scheme(Signature_Scheme::Code(wire_code)) {}

Signature_Scheme::Signature_Scheme(Signature_Scheme::Code wire_code) : m_code(wire_code) {}

bool Signature_Scheme::is_available() const noexcept {
   return value_exists(Signature_Scheme::all_available_schemes(), *this);
}

bool Signature_Scheme::is_set() const noexcept {
   return m_code != NONE;
}

std::string Signature_Scheme::to_string() const noexcept {
   switch(m_code) {
      case RSA_PKCS1_SHA1:
         return "RSA_PKCS1_SHA1";
      case RSA_PKCS1_SHA256:
         return "RSA_PKCS1_SHA256";
      case RSA_PKCS1_SHA384:
         return "RSA_PKCS1_SHA384";
      case RSA_PKCS1_SHA512:
         return "RSA_PKCS1_SHA512";

      case ECDSA_SHA1:
         return "ECDSA_SHA1";
      case ECDSA_SHA256:
         return "ECDSA_SHA256";
      case ECDSA_SHA384:
         return "ECDSA_SHA384";
      case ECDSA_SHA512:
         return "ECDSA_SHA512";

      case RSA_PSS_SHA256:
         return "RSA_PSS_SHA256";
      case RSA_PSS_SHA384:
         return "RSA_PSS_SHA384";
      case RSA_PSS_SHA512:
         return "RSA_PSS_SHA512";

      case EDDSA_25519:
         return "EDDSA_25519";
      case EDDSA_448:
         return "EDDSA_448";

      default:
         return "Unknown signature scheme: " + std::to_string(m_code);
   }
}

std::string Signature_Scheme::hash_function_name() const noexcept {
   switch(m_code) {
      case RSA_PKCS1_SHA1:
      case ECDSA_SHA1:
         return "SHA-1";

      case ECDSA_SHA256:
      case RSA_PKCS1_SHA256:
      case RSA_PSS_SHA256:
         return "SHA-256";

      case ECDSA_SHA384:
      case RSA_PKCS1_SHA384:
      case RSA_PSS_SHA384:
         return "SHA-384";

      case ECDSA_SHA512:
      case RSA_PKCS1_SHA512:
      case RSA_PSS_SHA512:
         return "SHA-512";

      case EDDSA_25519:
      case EDDSA_448:
         return "Pure";

      default:
         return "Unknown hash function";
   }
}

std::string Signature_Scheme::padding_string() const noexcept {
   switch(m_code) {
      case RSA_PKCS1_SHA1:
         return "PKCS1v15(SHA-1)";
      case RSA_PKCS1_SHA256:
         return "PKCS1v15(SHA-256)";
      case RSA_PKCS1_SHA384:
         return "PKCS1v15(SHA-384)";
      case RSA_PKCS1_SHA512:
         return "PKCS1v15(SHA-512)";

      case ECDSA_SHA1:
         return "SHA-1";
      case ECDSA_SHA256:
         return "SHA-256";
      case ECDSA_SHA384:
         return "SHA-384";
      case ECDSA_SHA512:
         return "SHA-512";

      case RSA_PSS_SHA256:
         return "PSS(SHA-256,MGF1,32)";
      case RSA_PSS_SHA384:
         return "PSS(SHA-384,MGF1,48)";
      case RSA_PSS_SHA512:
         return "PSS(SHA-512,MGF1,64)";

      case EDDSA_25519:
         return "Pure";
      case EDDSA_448:
         return "Pure";

      default:
         return "Unknown padding";
   }
}

std::string Signature_Scheme::algorithm_name() const noexcept {
   switch(m_code) {
      case RSA_PKCS1_SHA1:
      case RSA_PKCS1_SHA256:
      case RSA_PKCS1_SHA384:
      case RSA_PKCS1_SHA512:
      case RSA_PSS_SHA256:
      case RSA_PSS_SHA384:
      case RSA_PSS_SHA512:
         return "RSA";

      case ECDSA_SHA1:
      case ECDSA_SHA256:
      case ECDSA_SHA384:
      case ECDSA_SHA512:
         return "ECDSA";

      case EDDSA_25519:
         return "Ed25519";

      case EDDSA_448:
         return "Ed448";

      default:
         return "Unknown algorithm";
   }
}

AlgorithmIdentifier Signature_Scheme::key_algorithm_identifier() const noexcept {
   switch(m_code) {
      // case ECDSA_SHA1:  not defined
      case ECDSA_SHA256:
         return {"ECDSA", EC_Group::from_name("secp256r1").DER_encode()};
      case ECDSA_SHA384:
         return {"ECDSA", EC_Group::from_name("secp384r1").DER_encode()};
      case ECDSA_SHA512:
         return {"ECDSA", EC_Group::from_name("secp521r1").DER_encode()};

      case EDDSA_25519:
         return {"Ed25519", AlgorithmIdentifier::USE_EMPTY_PARAM};
      case EDDSA_448:
         return {"Ed448", AlgorithmIdentifier::USE_EMPTY_PARAM};

      case RSA_PKCS1_SHA1:
      case RSA_PKCS1_SHA256:
      case RSA_PKCS1_SHA384:
      case RSA_PKCS1_SHA512:
      case RSA_PSS_SHA256:
      case RSA_PSS_SHA384:
      case RSA_PSS_SHA512:
         return {"RSA", AlgorithmIdentifier::USE_NULL_PARAM};

      default:
         return AlgorithmIdentifier();
   }
}

AlgorithmIdentifier Signature_Scheme::algorithm_identifier() const noexcept {
   switch(m_code) {
      case RSA_PKCS1_SHA1:
         return AlgorithmIdentifier(OID::from_string("RSA/PKCS1v15(SHA-1)"), AlgorithmIdentifier::USE_NULL_PARAM);
      case RSA_PKCS1_SHA256:
         return AlgorithmIdentifier(OID::from_string("RSA/PKCS1v15(SHA-256)"), AlgorithmIdentifier::USE_NULL_PARAM);
      case RSA_PKCS1_SHA384:
         return AlgorithmIdentifier(OID::from_string("RSA/PKCS1v15(SHA-384)"), AlgorithmIdentifier::USE_NULL_PARAM);
      case RSA_PKCS1_SHA512:
         return AlgorithmIdentifier(OID::from_string("RSA/PKCS1v15(SHA-512)"), AlgorithmIdentifier::USE_NULL_PARAM);

      case ECDSA_SHA1:
         return AlgorithmIdentifier(OID::from_string("ECDSA/SHA-1"), AlgorithmIdentifier::USE_EMPTY_PARAM);
      case ECDSA_SHA256:
         return AlgorithmIdentifier(OID::from_string("ECDSA/SHA-256"), AlgorithmIdentifier::USE_EMPTY_PARAM);
      case ECDSA_SHA384:
         return AlgorithmIdentifier(OID::from_string("ECDSA/SHA-384"), AlgorithmIdentifier::USE_EMPTY_PARAM);
      case ECDSA_SHA512:
         return AlgorithmIdentifier(OID::from_string("ECDSA/SHA-512"), AlgorithmIdentifier::USE_EMPTY_PARAM);

      case RSA_PSS_SHA256:
         return AlgorithmIdentifier(OID::from_string("RSA/PSS"), PSS_Params("SHA-256", 32).serialize());
      case RSA_PSS_SHA384:
         return AlgorithmIdentifier(OID::from_string("RSA/PSS"), PSS_Params("SHA-384", 48).serialize());
      case RSA_PSS_SHA512:
         return AlgorithmIdentifier(OID::from_string("RSA/PSS"), PSS_Params("SHA-512", 64).serialize());

      default:
         // Note that Ed25519 and Ed448 end up here
         return AlgorithmIdentifier();
   }
}

std::optional<Signature_Format> Signature_Scheme::format() const noexcept {
   switch(m_code) {
      case RSA_PKCS1_SHA1:
      case RSA_PKCS1_SHA256:
      case RSA_PKCS1_SHA384:
      case RSA_PKCS1_SHA512:
      case RSA_PSS_SHA256:
      case RSA_PSS_SHA384:
      case RSA_PSS_SHA512:
         return Signature_Format::Standard;

      case ECDSA_SHA1:
      case ECDSA_SHA256:
      case ECDSA_SHA384:
      case ECDSA_SHA512:
      case EDDSA_25519:
      case EDDSA_448:
         return Signature_Format::DerSequence;

      default:
         return std::nullopt;
   }
}

bool Signature_Scheme::is_compatible_with(const Protocol_Version& protocol_version) const noexcept {
   // RFC 8446 4.4.3:
   //   The SHA-1 algorithm MUST NOT be used in any signatures of
   //   CertificateVerify messages.
   //
   // Note that Botan enforces that for TLS 1.2 as well.
   if(hash_function_name() == "SHA-1") {
      return false;
   }

   // RFC 8446 4.4.3:
   //   RSA signatures MUST use an RSASSA-PSS algorithm, regardless of whether
   //   RSASSA-PKCS1-v1_5 algorithms appear in "signature_algorithms".
   //
   // Note that this is enforced for TLS 1.3 and above only.
   if(!protocol_version.is_pre_tls_13() && (m_code == RSA_PKCS1_SHA1 || m_code == RSA_PKCS1_SHA256 ||
                                            m_code == RSA_PKCS1_SHA384 || m_code == RSA_PKCS1_SHA512)) {
      return false;
   }

   return true;
}

bool Signature_Scheme::is_suitable_for(const Private_Key& private_key) const noexcept {
   if(algorithm_name() != private_key.algo_name()) {
      return false;
   }

   // The ECDSA private key length must match the utilized hash output length.
   const auto keylen = private_key.key_length();
   if(keylen <= 250) {
      return false;
   }

   if(m_code == ECDSA_SHA256 && !(keylen >= 250 && keylen <= 350)) {
      return false;
   }

   if(m_code == ECDSA_SHA384 && !(keylen >= 350 && keylen <= 450)) {
      return false;
   }

   if(m_code == ECDSA_SHA512 && !(keylen >= 450 && keylen <= 550)) {
      return false;
   }

   return true;
}

std::vector<AlgorithmIdentifier> to_algorithm_identifiers(const std::vector<Signature_Scheme>& schemes) {
   std::vector<AlgorithmIdentifier> result;
   std::transform(schemes.begin(), schemes.end(), std::back_inserter(result), [](const auto& scheme) {
      return scheme.algorithm_identifier();
   });
   return result;
}

}  // namespace Botan::TLS
