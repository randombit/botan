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
      case Kex_Algo::PSK:
         return "PSK";
      case Kex_Algo::ECDHE_PSK:
         return "ECDHE_PSK";
      case Kex_Algo::UNDEFINED:
         return "UNDEFINED";
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

   if(str == "PSK")
      return Kex_Algo::PSK;

   if(str == "ECDHE_PSK")
      return Kex_Algo::ECDHE_PSK;

   if(str == "UNDEFINED")
      return Kex_Algo::UNDEFINED;

   throw Invalid_Argument("Unknown kex method " + str);
   }

std::string auth_method_to_string(Auth_Method method)
   {
   switch(method)
      {
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

Auth_Method auth_method_from_string(const std::string& str)
   {
   if(str == "RSA")
      return Auth_Method::RSA;
   if(str == "ECDSA")
      return Auth_Method::ECDSA;
   if(str == "IMPLICIT")
      return Auth_Method::IMPLICIT;
   if(str == "UNDEFINED")
      return Auth_Method::UNDEFINED;
      
   throw Invalid_Argument("Bad signature method " + str);
   }

bool group_param_is_dh(Group_Params group)
   {
   uint16_t group_id = static_cast<uint16_t>(group);
   return (group_id >= 256 && group_id < 512);
   }

Group_Params group_param_from_string(const std::string& group_name)
   {
   if(group_name == "secp256r1")
      return Group_Params::SECP256R1;
   if(group_name == "secp384r1")
      return Group_Params::SECP384R1;
   if(group_name == "secp521r1")
      return Group_Params::SECP521R1;
   if(group_name == "brainpool256r1")
      return Group_Params::BRAINPOOL256R1;
   if(group_name == "brainpool384r1")
      return Group_Params::BRAINPOOL384R1;
   if(group_name == "brainpool512r1")
      return Group_Params::BRAINPOOL512R1;
   if(group_name == "x25519")
      return Group_Params::X25519;

   if(group_name == "ffdhe/ietf/2048")
      return Group_Params::FFDHE_2048;
   if(group_name == "ffdhe/ietf/3072")
      return Group_Params::FFDHE_3072;
   if(group_name == "ffdhe/ietf/4096")
      return Group_Params::FFDHE_4096;
   if(group_name == "ffdhe/ietf/6144")
      return Group_Params::FFDHE_6144;
   if(group_name == "ffdhe/ietf/8192")
      return Group_Params::FFDHE_8192;

   return Group_Params::NONE; // unknown
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

      default:
         return "";
      }
   }


std::string hash_function_of_scheme(Signature_Scheme scheme)
   {
   switch(scheme)
      {
      case Signature_Scheme::ECDSA_SHA256:
      case Signature_Scheme::RSA_PKCS1_SHA256:
      case Signature_Scheme::RSA_PSS_SHA256:
         return "SHA-256";

      case Signature_Scheme::ECDSA_SHA384:
      case Signature_Scheme::RSA_PKCS1_SHA384:
      case Signature_Scheme::RSA_PSS_SHA384:
         return "SHA-384";

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

   throw Invalid_State("hash_function_of_scheme: Unknown signature algorithm enum");
   }

const std::vector<Signature_Scheme>& all_signature_schemes()
   {
   /*
   * This is ordered in some approximate order of preference
   */
   static const std::vector<Signature_Scheme> all_schemes = {
      //Signature_Scheme::EDDSA_448,
      //Signature_Scheme::EDDSA_25519,

      Signature_Scheme::RSA_PSS_SHA384,
      Signature_Scheme::RSA_PSS_SHA256,
      Signature_Scheme::RSA_PSS_SHA512,

      Signature_Scheme::RSA_PKCS1_SHA384,
      Signature_Scheme::RSA_PKCS1_SHA512,
      Signature_Scheme::RSA_PKCS1_SHA256,

      Signature_Scheme::ECDSA_SHA384,
      Signature_Scheme::ECDSA_SHA512,
      Signature_Scheme::ECDSA_SHA256,
   };

   return all_schemes;
   }

bool signature_scheme_is_known(Signature_Scheme scheme)
   {
   switch(scheme)
      {
      case Signature_Scheme::RSA_PKCS1_SHA256:
      case Signature_Scheme::RSA_PKCS1_SHA384:
      case Signature_Scheme::RSA_PKCS1_SHA512:
      case Signature_Scheme::RSA_PSS_SHA256:
      case Signature_Scheme::RSA_PSS_SHA384:
      case Signature_Scheme::RSA_PSS_SHA512:

      case Signature_Scheme::ECDSA_SHA256:
      case Signature_Scheme::ECDSA_SHA384:
      case Signature_Scheme::ECDSA_SHA512:
         return true;

      default:
         return false;
      }

   }

std::string signature_algorithm_of_scheme(Signature_Scheme scheme)
   {
   switch(scheme)
      {
      case Signature_Scheme::RSA_PKCS1_SHA256:
      case Signature_Scheme::RSA_PKCS1_SHA384:
      case Signature_Scheme::RSA_PKCS1_SHA512:
      case Signature_Scheme::RSA_PSS_SHA256:
      case Signature_Scheme::RSA_PSS_SHA384:
      case Signature_Scheme::RSA_PSS_SHA512:
         return "RSA";

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

   throw Invalid_State("signature_algorithm_of_scheme: Unknown signature algorithm enum");
   }

std::string sig_scheme_to_string(Signature_Scheme scheme)
   {
   switch(scheme)
      {
      case Signature_Scheme::RSA_PKCS1_SHA256:
         return "RSA_PKCS1_SHA256";
      case Signature_Scheme::RSA_PKCS1_SHA384:
         return "RSA_PKCS1_SHA384";
      case Signature_Scheme::RSA_PKCS1_SHA512:
         return "RSA_PKCS1_SHA512";

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

   throw Invalid_State("sig_scheme_to_string: Unknown signature algorithm enum");
   }

std::string padding_string_for_scheme(Signature_Scheme scheme)
   {
   switch(scheme)
      {
      case Signature_Scheme::RSA_PKCS1_SHA256:
         return "EMSA_PKCS1(SHA-256)";
      case Signature_Scheme::RSA_PKCS1_SHA384:
         return "EMSA_PKCS1(SHA-384)";
      case Signature_Scheme::RSA_PKCS1_SHA512:
         return "EMSA_PKCS1(SHA-512)";

      case Signature_Scheme::ECDSA_SHA256:
         return "EMSA1(SHA-256)";
      case Signature_Scheme::ECDSA_SHA384:
         return "EMSA1(SHA-384)";
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

   throw Invalid_State("padding_string_for_scheme: Unknown signature algorithm enum");
   }

}

}
