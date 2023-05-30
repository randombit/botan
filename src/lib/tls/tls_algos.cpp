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

bool group_param_is_dh(Group_Params group) {
   uint16_t group_id = static_cast<uint16_t>(group);
   return (group_id >= 256 && group_id < 512);
}

Group_Params group_param_from_string(std::string_view group_name) {
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

   return Group_Params::NONE;  // unknown
}

std::string group_param_to_string(Group_Params group) {
   switch(group) {
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

}  // namespace Botan::TLS
