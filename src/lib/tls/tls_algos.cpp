/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_algos.h>
#include <botan/exceptn.h>

namespace Botan {

namespace TLS {

std::string kdf_algo_to_string(KDF_Algo algo)
   {
   switch(algo)
      {
      case KDF_Algo::SHA_1:
         return "SHA-1";
      case KDF_Algo::SHA_256:
         return "SHA-256";
      case KDF_Algo::SHA_384:
         return "SHA-384";
      }

   throw Invalid_State("kdf_algo_to_string unknown enum value");
   }

std::string kex_method_to_string(Kex_Algo method)
   {
   switch(method)
      {
      case Kex_Algo::STATIC_RSA:
         return "RSA";
      case Kex_Algo::DH:
         return "DH";
      case Kex_Algo::ECDH:
         return "ECDH";
      case Kex_Algo::CECPQ1:
         return "CECPQ1";
      case Kex_Algo::SRP_SHA:
         return "SRP_SHA";
      case Kex_Algo::PSK:
         return "PSK";
      case Kex_Algo::DHE_PSK:
         return "DHE_PSK";
      case Kex_Algo::ECDHE_PSK:
         return "ECDHE_PSK";
      }

   throw Invalid_State("kex_method_to_string unknown enum value");
   }

Kex_Algo kex_method_from_string(const std::string& str)
   {
   if(str == "RSA")
      return Kex_Algo::STATIC_RSA;

   if(str == "DH")
      return Kex_Algo::DH;

   if(str == "ECDH")
      return Kex_Algo::ECDH;

   if(str == "CECPQ1")
      return Kex_Algo::CECPQ1;

   if(str == "SRP_SHA")
      return Kex_Algo::SRP_SHA;

   if(str == "PSK")
      return Kex_Algo::PSK;

   if(str == "DHE_PSK")
      return Kex_Algo::DHE_PSK;

   if(str == "ECDHE_PSK")
      return Kex_Algo::ECDHE_PSK;

   throw Invalid_Argument("Unknown kex method " + str);
   }

std::string auth_method_to_string(Auth_Method method)
   {
   switch(method)
      {
      case Auth_Method::RSA:
         return "RSA";
      case Auth_Method::DSA:
         return "DSA";
      case Auth_Method::ECDSA:
         return "ECDSA";
      case Auth_Method::IMPLICIT:
         return "IMPLICIT";
      case Auth_Method::ANONYMOUS:
         return "ANONYMOUS";
      }

    throw Invalid_State("auth_method_to_string unknown enum value");
   }

Auth_Method auth_method_from_string(const std::string& str)
   {
   if(str == "RSA")
      return Auth_Method::RSA;
   if(str == "DSA")
      return Auth_Method::DSA;
   if(str == "ECDSA")
      return Auth_Method::ECDSA;
   if(str == "ANONYMOUS" || str == "")
      return Auth_Method::ANONYMOUS;

   throw Invalid_Argument("Bad signature method " + str);
   }

std::string group_param_to_string(Group_Params group)
   {
   switch(group)
      {
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

#if defined(BOTAN_HOUSE_ECC_CURVE_NAME)
      case BOTAN_HOUSE_ECC_CURVE_TLS_ID:
         return BOTAN_HOUSE_ECC_CURVE_NAME;
#endif

      default:
         return "";
      }
   }


std::string hash_function_of_scheme(Signature_Scheme scheme)
   {
   switch(scheme)
      {
      case Signature_Scheme::DSA_SHA1:
      case Signature_Scheme::ECDSA_SHA1:
      case Signature_Scheme::RSA_PKCS1_SHA1:
         return "SHA-1";

      case Signature_Scheme::DSA_SHA256:
      case Signature_Scheme::ECDSA_SHA256:
      case Signature_Scheme::RSA_PKCS1_SHA256:
      case Signature_Scheme::RSA_PSS_SHA256:
         return "SHA-256";

      case Signature_Scheme::DSA_SHA384:
      case Signature_Scheme::ECDSA_SHA384:
      case Signature_Scheme::RSA_PKCS1_SHA384:
      case Signature_Scheme::RSA_PSS_SHA384:
         return "SHA-384";

      case Signature_Scheme::DSA_SHA512:
      case Signature_Scheme::ECDSA_SHA512:
      case Signature_Scheme::RSA_PKCS1_SHA512:
      case Signature_Scheme::RSA_PSS_SHA512:
         return "SHA-512";

      case Signature_Scheme::EDDSA_25519:
      case Signature_Scheme::EDDSA_448:
         return "Pure";

      case Signature_Scheme::NONE:
         return "";
      }

   throw Invalid_State("Unknown signature algorithm enum");
   }

const std::vector<Signature_Scheme>& all_signature_schemes()
   {
   static const std::vector<Signature_Scheme> all_schemes = {
      Signature_Scheme::RSA_PKCS1_SHA1,
      Signature_Scheme::RSA_PKCS1_SHA256,
      Signature_Scheme::RSA_PKCS1_SHA384,
      Signature_Scheme::RSA_PKCS1_SHA512,
      Signature_Scheme::DSA_SHA1,
      Signature_Scheme::DSA_SHA256,
      Signature_Scheme::DSA_SHA384,
      Signature_Scheme::DSA_SHA512,
      Signature_Scheme::ECDSA_SHA1,
      Signature_Scheme::ECDSA_SHA256,
      Signature_Scheme::ECDSA_SHA384,
      Signature_Scheme::ECDSA_SHA512,
      Signature_Scheme::RSA_PSS_SHA256,
      Signature_Scheme::RSA_PSS_SHA384,
      Signature_Scheme::RSA_PSS_SHA512,
      Signature_Scheme::EDDSA_25519,
      Signature_Scheme::EDDSA_448,
   };

   return all_schemes;
   }

std::string signature_algorithm_of_scheme(Signature_Scheme scheme)
   {
   switch(scheme)
      {
      case Signature_Scheme::RSA_PKCS1_SHA1:
      case Signature_Scheme::RSA_PKCS1_SHA256:
      case Signature_Scheme::RSA_PKCS1_SHA384:
      case Signature_Scheme::RSA_PKCS1_SHA512:
      case Signature_Scheme::RSA_PSS_SHA256:
      case Signature_Scheme::RSA_PSS_SHA384:
      case Signature_Scheme::RSA_PSS_SHA512:
         return "RSA";

      case Signature_Scheme::DSA_SHA1:
      case Signature_Scheme::DSA_SHA256:
      case Signature_Scheme::DSA_SHA384:
      case Signature_Scheme::DSA_SHA512:
         return "DSA";

      case Signature_Scheme::ECDSA_SHA1:
      case Signature_Scheme::ECDSA_SHA256:
      case Signature_Scheme::ECDSA_SHA384:
      case Signature_Scheme::ECDSA_SHA512:
         return "ECDSA";

      case Signature_Scheme::EDDSA_25519:
         return "Ed25519";

      case Signature_Scheme::EDDSA_448:
         return "Ed448";

      case Signature_Scheme::NONE:
         return "";
      }

   throw Invalid_State("Unknown signature algorithm enum");
   }

std::string sig_scheme_to_string(Signature_Scheme scheme)
   {
   switch(scheme)
      {
      case Signature_Scheme::RSA_PKCS1_SHA1:
         return "RSA_PKCS1_SHA1";
      case Signature_Scheme::RSA_PKCS1_SHA256:
         return "RSA_PKCS1_SHA256";
      case Signature_Scheme::RSA_PKCS1_SHA384:
         return "RSA_PKCS1_SHA384";
      case Signature_Scheme::RSA_PKCS1_SHA512:
         return "RSA_PKCS1_SHA512";

      case Signature_Scheme::DSA_SHA1:
         return "DSA_SHA1";
      case Signature_Scheme::DSA_SHA256:
         return "DSA_SHA256";
      case Signature_Scheme::DSA_SHA384:
         return "DSA_SHA384";
      case Signature_Scheme::DSA_SHA512:
         return "DSA_SHA512";

      case Signature_Scheme::ECDSA_SHA1:
         return "ECDSA_SHA1";
      case Signature_Scheme::ECDSA_SHA256:
         return "ECDSA_SHA256";
      case Signature_Scheme::ECDSA_SHA384:
         return "ECDSA_SHA384";
      case Signature_Scheme::ECDSA_SHA512:
         return "ECDSA_SHA512";

      case Signature_Scheme::RSA_PSS_SHA256:
         return "RSA_PSS_SHA256";
      case Signature_Scheme::RSA_PSS_SHA384:
         return "RSA_PSS_SHA384";
      case Signature_Scheme::RSA_PSS_SHA512:
         return "RSA_PSS_SHA512";

      case Signature_Scheme::EDDSA_25519:
         return "EDDSA_25519";
      case Signature_Scheme::EDDSA_448:
         return "EDDSA_448";

      case Signature_Scheme::NONE:
         return "";
      }

   throw Invalid_State("Unknown signature algorithm enum");
   }

std::string padding_string_for_scheme(Signature_Scheme scheme)
   {
   switch(scheme)
      {
      case Signature_Scheme::RSA_PKCS1_SHA1:
         return "EMSA_PKCS1(SHA-1)";
      case Signature_Scheme::RSA_PKCS1_SHA256:
         return "EMSA_PKCS1(SHA-256)";
      case Signature_Scheme::RSA_PKCS1_SHA384:
         return "EMSA_PKCS1(SHA-384)";
      case Signature_Scheme::RSA_PKCS1_SHA512:
         return "EMSA_PKCS1(SHA-512)";

      case Signature_Scheme::DSA_SHA1:
      case Signature_Scheme::ECDSA_SHA1:
         return "EMSA1(SHA-1)";
      case Signature_Scheme::DSA_SHA256:
      case Signature_Scheme::ECDSA_SHA256:
         return "EMSA1(SHA-256)";
      case Signature_Scheme::DSA_SHA384:
      case Signature_Scheme::ECDSA_SHA384:
         return "EMSA1(SHA-384)";
      case Signature_Scheme::DSA_SHA512:
      case Signature_Scheme::ECDSA_SHA512:
         return "EMSA1(SHA-512)";

      case Signature_Scheme::RSA_PSS_SHA256:
         return "PSSR(SHA-256,MGF1,32)";
      case Signature_Scheme::RSA_PSS_SHA384:
         return "PSSR(SHA-384,MGF1,48)";
      case Signature_Scheme::RSA_PSS_SHA512:
         return "PSSR(SHA-512,MGF1,64)";

      case Signature_Scheme::EDDSA_25519:
         return "Pure";
      case Signature_Scheme::EDDSA_448:
         return "Pure";

      case Signature_Scheme::NONE:
         return "";
      }

   throw Invalid_State("Unknown signature algorithm enum");
   }

}

}
