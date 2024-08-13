/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_algos.h>

#include <botan/ec_group.h>
#include <botan/exceptn.h>
#include <botan/internal/fmt.h>

namespace Botan::TLS {

std::string kdf_algo_to_string(KDF_Algo algo) {
   switch(algo) {
      case KDF_Algo::SHA_1:
         return "SHA-1";
      case KDF_Algo::SHA_256:
         return "SHA-256";
      case KDF_Algo::SHA_384:
         return "SHA-384";
   }

   throw Invalid_State("kdf_algo_to_string unknown enum value");
}

std::string kex_method_to_string(Kex_Algo method) {
   switch(method) {
      case Kex_Algo::STATIC_RSA:
         return "RSA";
      case Kex_Algo::DH:
         return "DH";
      case Kex_Algo::ECDH:
         return "ECDH";
      case Kex_Algo::PSK:
         return "PSK";
      case Kex_Algo::ECDHE_PSK:
         return "ECDHE_PSK";
      case Kex_Algo::DHE_PSK:
         return "DHE_PSK";
      case Kex_Algo::KEM:
         return "KEM";
      case Kex_Algo::KEM_PSK:
         return "KEM_PSK";
      case Kex_Algo::HYBRID:
         return "HYBRID";
      case Kex_Algo::HYBRID_PSK:
         return "HYBRID_PSK";
      case Kex_Algo::UNDEFINED:
         return "UNDEFINED";
   }

   throw Invalid_State("kex_method_to_string unknown enum value");
}

Kex_Algo kex_method_from_string(std::string_view str) {
   if(str == "RSA") {
      return Kex_Algo::STATIC_RSA;
   }

   if(str == "DH") {
      return Kex_Algo::DH;
   }

   if(str == "ECDH") {
      return Kex_Algo::ECDH;
   }

   if(str == "PSK") {
      return Kex_Algo::PSK;
   }

   if(str == "ECDHE_PSK") {
      return Kex_Algo::ECDHE_PSK;
   }

   if(str == "DHE_PSK") {
      return Kex_Algo::DHE_PSK;
   }

   if(str == "KEM") {
      return Kex_Algo::KEM;
   }

   if(str == "KEM_PSK") {
      return Kex_Algo::KEM_PSK;
   }

   if(str == "HYBRID") {
      return Kex_Algo::HYBRID;
   }

   if(str == "HYBRID_PSK") {
      return Kex_Algo::HYBRID_PSK;
   }

   if(str == "UNDEFINED") {
      return Kex_Algo::UNDEFINED;
   }

   throw Invalid_Argument(fmt("Unknown kex method '{}'", str));
}

std::string auth_method_to_string(Auth_Method method) {
   switch(method) {
      case Auth_Method::RSA:
         return "RSA";
      case Auth_Method::ECDSA:
         return "ECDSA";
      case Auth_Method::IMPLICIT:
         return "IMPLICIT";
      case Auth_Method::UNDEFINED:
         return "UNDEFINED";
   }

   throw Invalid_State("auth_method_to_string unknown enum value");
}

Auth_Method auth_method_from_string(std::string_view str) {
   if(str == "RSA") {
      return Auth_Method::RSA;
   }
   if(str == "ECDSA") {
      return Auth_Method::ECDSA;
   }
   if(str == "IMPLICIT") {
      return Auth_Method::IMPLICIT;
   }
   if(str == "UNDEFINED") {
      return Auth_Method::UNDEFINED;
   }

   throw Invalid_Argument(fmt("Unknown TLS signature method '{}'", str));
}

bool Group_Params::is_available() const {
#if !defined(BOTAN_HAS_X25519)
   if(is_x25519()) {
      return false;
   }
   if(is_pqc_hybrid() && pqc_hybrid_ecc() == Group_Params_Code::X25519) {
      return false;
   }
#endif

#if !defined(BOTAN_HAS_X448)
   if(is_x448()) {
      return false;
   }
   if(is_pqc_hybrid() && pqc_hybrid_ecc() == Group_Params_Code::X448) {
      return false;
   }
#endif

#if !defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(is_in_ffdhe_range()) {
      return false;
   }
#endif

#if !defined(BOTAN_HAS_KYBER_ROUND3)
   if(is_pure_kyber_r3() || is_pqc_hybrid_kyber_r3()) {
      return false;
   }
#endif

#if !defined(BOTAN_HAS_ML_KEM)
   if(is_pqc_hybrid_ml_kem()) {
      return false;
   }
#endif

#if !defined(BOTAN_HAS_FRODOKEM)
   if(is_pure_frodokem() || is_pqc_hybrid_frodokem()) {
      return false;
   }
#endif

   return true;
}

std::optional<Group_Params_Code> Group_Params::pqc_hybrid_ecc() const {
   switch(m_code) {
      case Group_Params_Code::HYBRID_X25519_ML_KEM_768:
      case Group_Params_Code::HYBRID_X25519_KYBER_512_R3_CLOUDFLARE:
      case Group_Params_Code::HYBRID_X25519_KYBER_512_R3_OQS:
      case Group_Params_Code::HYBRID_X25519_KYBER_768_R3_OQS:
      case Group_Params_Code::HYBRID_X25519_eFRODOKEM_640_SHAKE_OQS:
      case Group_Params_Code::HYBRID_X25519_eFRODOKEM_640_AES_OQS:
         return Group_Params_Code::X25519;

      case Group_Params_Code::HYBRID_X448_KYBER_768_R3_OQS:
      case Group_Params_Code::HYBRID_X448_eFRODOKEM_976_SHAKE_OQS:
      case Group_Params_Code::HYBRID_X448_eFRODOKEM_976_AES_OQS:
         return Group_Params_Code::X448;

      case Group_Params_Code::HYBRID_SECP256R1_ML_KEM_768:
      case Group_Params_Code::HYBRID_SECP256R1_KYBER_512_R3_OQS:
      case Group_Params_Code::HYBRID_SECP256R1_KYBER_768_R3_OQS:
      case Group_Params_Code::HYBRID_SECP256R1_eFRODOKEM_640_SHAKE_OQS:
      case Group_Params_Code::HYBRID_SECP256R1_eFRODOKEM_640_AES_OQS:
         return Group_Params_Code::SECP256R1;

      case Group_Params_Code::HYBRID_SECP384R1_KYBER_768_R3_OQS:
      case Group_Params_Code::HYBRID_SECP384R1_eFRODOKEM_976_SHAKE_OQS:
      case Group_Params_Code::HYBRID_SECP384R1_eFRODOKEM_976_AES_OQS:
         return Group_Params_Code::SECP384R1;

      case Group_Params_Code::HYBRID_SECP521R1_KYBER_1024_R3_OQS:
      case Group_Params_Code::HYBRID_SECP521R1_eFRODOKEM_1344_SHAKE_OQS:
      case Group_Params_Code::HYBRID_SECP521R1_eFRODOKEM_1344_AES_OQS:
         return Group_Params_Code::SECP521R1;

      default:
         return {};
   }
}

std::optional<Group_Params> Group_Params::from_string(std::string_view group_name) {
   if(group_name == "secp256r1") {
      return Group_Params::SECP256R1;
   }
   if(group_name == "secp384r1") {
      return Group_Params::SECP384R1;
   }
   if(group_name == "secp521r1") {
      return Group_Params::SECP521R1;
   }
   if(group_name == "brainpool256r1") {
      return Group_Params::BRAINPOOL256R1;
   }
   if(group_name == "brainpool384r1") {
      return Group_Params::BRAINPOOL384R1;
   }
   if(group_name == "brainpool512r1") {
      return Group_Params::BRAINPOOL512R1;
   }
   if(group_name == "x25519") {
      return Group_Params::X25519;
   }
   if(group_name == "x448") {
      return Group_Params::X448;
   }

   if(group_name == "ffdhe/ietf/2048") {
      return Group_Params::FFDHE_2048;
   }
   if(group_name == "ffdhe/ietf/3072") {
      return Group_Params::FFDHE_3072;
   }
   if(group_name == "ffdhe/ietf/4096") {
      return Group_Params::FFDHE_4096;
   }
   if(group_name == "ffdhe/ietf/6144") {
      return Group_Params::FFDHE_6144;
   }
   if(group_name == "ffdhe/ietf/8192") {
      return Group_Params::FFDHE_8192;
   }

   if(group_name == "Kyber-512-r3") {
      return Group_Params::KYBER_512_R3_OQS;
   }
   if(group_name == "Kyber-768-r3") {
      return Group_Params::KYBER_768_R3_OQS;
   }
   if(group_name == "Kyber-1024-r3") {
      return Group_Params::KYBER_1024_R3_OQS;
   }

   if(group_name == "eFrodoKEM-640-SHAKE") {
      return Group_Params::eFRODOKEM_640_SHAKE_OQS;
   }
   if(group_name == "eFrodoKEM-976-SHAKE") {
      return Group_Params::eFRODOKEM_976_SHAKE_OQS;
   }
   if(group_name == "eFrodoKEM-1344-SHAKE") {
      return Group_Params::eFRODOKEM_1344_SHAKE_OQS;
   }
   if(group_name == "eFrodoKEM-640-AES") {
      return Group_Params::eFRODOKEM_640_AES_OQS;
   }
   if(group_name == "eFrodoKEM-976-AES") {
      return Group_Params::eFRODOKEM_976_AES_OQS;
   }
   if(group_name == "eFrodoKEM-1344-AES") {
      return Group_Params::eFRODOKEM_1344_AES_OQS;
   }

   if(group_name == "x25519/Kyber-512-r3/cloudflare") {
      return Group_Params::HYBRID_X25519_KYBER_512_R3_CLOUDFLARE;
   }
   if(group_name == "x25519/Kyber-512-r3") {
      return Group_Params::HYBRID_X25519_KYBER_512_R3_OQS;
   }
   if(group_name == "x25519/Kyber-768-r3") {
      return Group_Params::HYBRID_X25519_KYBER_768_R3_OQS;
   }

   if(group_name == "x25519/ML-KEM-768") {
      return Group_Params::HYBRID_X25519_ML_KEM_768;
   }
   if(group_name == "secp256r1/ML-KEM-768") {
      return Group_Params::HYBRID_SECP256R1_ML_KEM_768;
   }

   if(group_name == "x448/Kyber-768-r3") {
      return Group_Params::HYBRID_X448_KYBER_768_R3_OQS;
   }
   if(group_name == "x25519/eFrodoKEM-640-SHAKE") {
      return Group_Params::HYBRID_X25519_eFRODOKEM_640_SHAKE_OQS;
   }
   if(group_name == "x25519/eFrodoKEM-640-AES") {
      return Group_Params::HYBRID_X25519_eFRODOKEM_640_AES_OQS;
   }
   if(group_name == "x448/eFrodoKEM-976-SHAKE") {
      return Group_Params::HYBRID_X448_eFRODOKEM_976_SHAKE_OQS;
   }
   if(group_name == "x448/eFrodoKEM-976-AES") {
      return Group_Params::HYBRID_X448_eFRODOKEM_976_AES_OQS;
   }

   if(group_name == "secp256r1/Kyber-512-r3") {
      return Group_Params::HYBRID_SECP256R1_KYBER_512_R3_OQS;
   }
   if(group_name == "secp256r1/Kyber-768-r3") {
      return Group_Params::HYBRID_SECP256R1_KYBER_768_R3_OQS;
   }
   if(group_name == "secp256r1/eFrodoKEM-640-SHAKE") {
      return Group_Params::HYBRID_SECP256R1_eFRODOKEM_640_SHAKE_OQS;
   }
   if(group_name == "secp256r1/eFrodoKEM-640-AES") {
      return Group_Params::HYBRID_SECP256R1_eFRODOKEM_640_AES_OQS;
   }

   if(group_name == "secp384r1/Kyber-768-r3") {
      return Group_Params::HYBRID_SECP384R1_KYBER_768_R3_OQS;
   }
   if(group_name == "secp384r1/eFrodoKEM-976-SHAKE") {
      return Group_Params::HYBRID_SECP384R1_eFRODOKEM_976_SHAKE_OQS;
   }
   if(group_name == "secp384r1/eFrodoKEM-976-AES") {
      return Group_Params::HYBRID_SECP384R1_eFRODOKEM_976_AES_OQS;
   }

   if(group_name == "secp521r1/Kyber-1024-r3") {
      return Group_Params::HYBRID_SECP521R1_KYBER_1024_R3_OQS;
   }
   if(group_name == "secp521r1/eFrodoKEM-1344-SHAKE") {
      return Group_Params::HYBRID_SECP521R1_eFRODOKEM_1344_SHAKE_OQS;
   }
   if(group_name == "secp521r1/eFrodoKEM-1344-AES") {
      return Group_Params::HYBRID_SECP521R1_eFRODOKEM_1344_AES_OQS;
   }

   return std::nullopt;
}

std::optional<std::string> Group_Params::to_string() const {
   switch(m_code) {
      case Group_Params::SECP256R1:
         return "secp256r1";
      case Group_Params::SECP384R1:
         return "secp384r1";
      case Group_Params::SECP521R1:
         return "secp521r1";
      case Group_Params::BRAINPOOL256R1:
         return "brainpool256r1";
      case Group_Params::BRAINPOOL384R1:
         return "brainpool384r1";
      case Group_Params::BRAINPOOL512R1:
         return "brainpool512r1";
      case Group_Params::X25519:
         return "x25519";
      case Group_Params::X448:
         return "x448";

      case Group_Params::FFDHE_2048:
         return "ffdhe/ietf/2048";
      case Group_Params::FFDHE_3072:
         return "ffdhe/ietf/3072";
      case Group_Params::FFDHE_4096:
         return "ffdhe/ietf/4096";
      case Group_Params::FFDHE_6144:
         return "ffdhe/ietf/6144";
      case Group_Params::FFDHE_8192:
         return "ffdhe/ietf/8192";

      case Group_Params::KYBER_512_R3_OQS:
         return "Kyber-512-r3";
      case Group_Params::KYBER_768_R3_OQS:
         return "Kyber-768-r3";
      case Group_Params::KYBER_1024_R3_OQS:
         return "Kyber-1024-r3";

      case Group_Params::eFRODOKEM_640_SHAKE_OQS:
         return "eFrodoKEM-640-SHAKE";
      case Group_Params::eFRODOKEM_976_SHAKE_OQS:
         return "eFrodoKEM-976-SHAKE";
      case Group_Params::eFRODOKEM_1344_SHAKE_OQS:
         return "eFrodoKEM-1344-SHAKE";
      case Group_Params::eFRODOKEM_640_AES_OQS:
         return "eFrodoKEM-640-AES";
      case Group_Params::eFRODOKEM_976_AES_OQS:
         return "eFrodoKEM-976-AES";
      case Group_Params::eFRODOKEM_1344_AES_OQS:
         return "eFrodoKEM-1344-AES";

      case Group_Params::HYBRID_X25519_eFRODOKEM_640_SHAKE_OQS:
         return "x25519/eFrodoKEM-640-SHAKE";
      case Group_Params::HYBRID_X25519_eFRODOKEM_640_AES_OQS:
         return "x25519/eFrodoKEM-640-AES";
      case Group_Params::HYBRID_X448_eFRODOKEM_976_SHAKE_OQS:
         return "x448/eFrodoKEM-976-SHAKE";
      case Group_Params::HYBRID_X448_eFRODOKEM_976_AES_OQS:
         return "x448/eFrodoKEM-976-AES";
      case Group_Params::HYBRID_SECP256R1_eFRODOKEM_640_SHAKE_OQS:
         return "secp256r1/eFrodoKEM-640-SHAKE";
      case Group_Params::HYBRID_SECP256R1_eFRODOKEM_640_AES_OQS:
         return "secp256r1/eFrodoKEM-640-AES";
      case Group_Params::HYBRID_SECP384R1_eFRODOKEM_976_SHAKE_OQS:
         return "secp384r1/eFrodoKEM-976-SHAKE";
      case Group_Params::HYBRID_SECP384R1_eFRODOKEM_976_AES_OQS:
         return "secp384r1/eFrodoKEM-976-AES";
      case Group_Params::HYBRID_SECP521R1_eFRODOKEM_1344_SHAKE_OQS:
         return "secp521r1/eFrodoKEM-1344-SHAKE";
      case Group_Params::HYBRID_SECP521R1_eFRODOKEM_1344_AES_OQS:
         return "secp521r1/eFrodoKEM-1344-AES";

      case Group_Params::HYBRID_X25519_KYBER_512_R3_CLOUDFLARE:
         return "x25519/Kyber-512-r3/cloudflare";

      case Group_Params::HYBRID_X25519_KYBER_512_R3_OQS:
         return "x25519/Kyber-512-r3";
      case Group_Params::HYBRID_X25519_KYBER_768_R3_OQS:
         return "x25519/Kyber-768-r3";

      case Group_Params::HYBRID_X25519_ML_KEM_768:
         return "x25519/ML-KEM-768";
      case Group_Params::HYBRID_SECP256R1_ML_KEM_768:
         return "secp256r1/ML-KEM-768";

      case Group_Params::HYBRID_X448_KYBER_768_R3_OQS:
         return "x448/Kyber-768-r3";

      case Group_Params::HYBRID_SECP256R1_KYBER_512_R3_OQS:
         return "secp256r1/Kyber-512-r3";
      case Group_Params::HYBRID_SECP256R1_KYBER_768_R3_OQS:
         return "secp256r1/Kyber-768-r3";
      case Group_Params::HYBRID_SECP384R1_KYBER_768_R3_OQS:
         return "secp384r1/Kyber-768-r3";
      case Group_Params::HYBRID_SECP521R1_KYBER_1024_R3_OQS:
         return "secp521r1/Kyber-1024-r3";

      default:
         return std::nullopt;
   }
}

}  // namespace Botan::TLS
