/*
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS)
   #include <botan/tls_signature_scheme.h>
#endif

#if defined(BOTAN_HAS_TLS)

namespace Botan_Tests {

namespace {

std::vector<Test::Result> test_signature_scheme() {
   std::vector<Test::Result> results;

   auto not_unknown = [](const std::string& s) { return s.find("Unknown") == std::string::npos; };

   for(const auto& s : Botan::TLS::Signature_Scheme::all_available_schemes()) {
      results.push_back(CHECK(s.to_string().c_str(), [&](auto& result) {
         result.test_is_true("is_set handles all cases", s.is_set());
         result.test_is_true("is_available handles all cases", s.is_available());

         result.test_is_true("to_string handles all cases", not_unknown(s.to_string()));
         result.test_u16_eq("to_string/from_string roundtrip",
                            Botan::TLS::Signature_Scheme::from_string(s.to_string()).wire_code(),
                            s.wire_code());
         result.test_is_true("hash_function_name handles all cases", not_unknown(s.hash_function_name()));
         result.test_is_true("padding_string handles all cases", not_unknown(s.padding_string()));
         result.test_is_true("algorithm_name handles all cases", not_unknown(s.algorithm_name()));

         result.test_is_true("format handles all cases", s.format().has_value());
         result.test_is_true("algorithm_identifier handles all cases",
                             Botan::AlgorithmIdentifier() != s.key_algorithm_identifier());
      }));
   }

   Botan::TLS::Signature_Scheme bogus(0x1337);
   results.push_back(CHECK("bogus scheme", [&](auto& result) {
      result.test_is_true("is_set still works", bogus.is_set());
      result.test_is_true("is not available", !bogus.is_available());

      result.test_is_true("to_string deals with bogus schemes", !not_unknown(bogus.to_string()));
      result.test_is_true("hash_function_name deals with bogus schemes", !not_unknown(bogus.hash_function_name()));
      result.test_is_true("padding_string deals with bogus schemes", !not_unknown(bogus.padding_string()));
      result.test_is_true("algorithm_name deals with bogus schemes", !not_unknown(bogus.algorithm_name()));

      result.test_is_true("format deals with bogus schemes", !bogus.format().has_value());
      result.test_is_true("algorithm_identifier deals with bogus schemes",
                          Botan::AlgorithmIdentifier() == bogus.key_algorithm_identifier());
   }));

   results.push_back(CHECK("from_string", [&](auto& result) {
      using Sig = Botan::TLS::Signature_Scheme;

      result.test_u16_eq("RSA_PKCS1_SHA1", Sig::from_string("RSA_PKCS1_SHA1").wire_code(), Sig::RSA_PKCS1_SHA1);
      result.test_u16_eq("RSA_PKCS1_SHA256", Sig::from_string("RSA_PKCS1_SHA256").wire_code(), Sig::RSA_PKCS1_SHA256);
      result.test_u16_eq("RSA_PKCS1_SHA384", Sig::from_string("RSA_PKCS1_SHA384").wire_code(), Sig::RSA_PKCS1_SHA384);
      result.test_u16_eq("RSA_PKCS1_SHA512", Sig::from_string("RSA_PKCS1_SHA512").wire_code(), Sig::RSA_PKCS1_SHA512);
      result.test_u16_eq("ECDSA_SHA1", Sig::from_string("ECDSA_SHA1").wire_code(), Sig::ECDSA_SHA1);
      result.test_u16_eq("ECDSA_SHA256", Sig::from_string("ECDSA_SHA256").wire_code(), Sig::ECDSA_SHA256);
      result.test_u16_eq("ECDSA_SECP256R1_TLS13_SHA256",
                         Sig::from_string("ECDSA_SECP256R1_TLS13_SHA256").wire_code(),
                         Sig::ECDSA_SECP256R1_TLS13_SHA256);
      result.test_u16_eq("ECDSA_SHA384", Sig::from_string("ECDSA_SHA384").wire_code(), Sig::ECDSA_SHA384);
      result.test_u16_eq("ECDSA_SECP384R1_TLS13_SHA384",
                         Sig::from_string("ECDSA_SECP384R1_TLS13_SHA384").wire_code(),
                         Sig::ECDSA_SECP384R1_TLS13_SHA384);
      result.test_u16_eq("ECDSA_SHA512", Sig::from_string("ECDSA_SHA512").wire_code(), Sig::ECDSA_SHA512);
      result.test_u16_eq("ECDSA_SECP521R1_TLS13_SHA512",
                         Sig::from_string("ECDSA_SECP521R1_TLS13_SHA512").wire_code(),
                         Sig::ECDSA_SECP521R1_TLS13_SHA512);
      result.test_u16_eq("RSA_PSS_SHA256", Sig::from_string("RSA_PSS_SHA256").wire_code(), Sig::RSA_PSS_SHA256);
      result.test_u16_eq("RSA_PSS_SHA384", Sig::from_string("RSA_PSS_SHA384").wire_code(), Sig::RSA_PSS_SHA384);
      result.test_u16_eq("RSA_PSS_SHA512", Sig::from_string("RSA_PSS_SHA512").wire_code(), Sig::RSA_PSS_SHA512);
      result.test_u16_eq("ECDSA_BRAINPOOL256R1_TLS13_SHA256",
                         Sig::from_string("ECDSA_BRAINPOOL256R1_TLS13_SHA256").wire_code(),
                         Sig::ECDSA_BRAINPOOL256R1_TLS13_SHA256);
      result.test_u16_eq("ECDSA_BRAINPOOL384R1_TLS13_SHA384",
                         Sig::from_string("ECDSA_BRAINPOOL384R1_TLS13_SHA384").wire_code(),
                         Sig::ECDSA_BRAINPOOL384R1_TLS13_SHA384);
      result.test_u16_eq("ECDSA_BRAINPOOL512R1_TLS13_SHA512",
                         Sig::from_string("ECDSA_BRAINPOOL512R1_TLS13_SHA512").wire_code(),
                         Sig::ECDSA_BRAINPOOL512R1_TLS13_SHA512);

      result.test_u16_eq("custom code point", Sig::from_string("0xFE42").wire_code(), Sig(0xFE42).wire_code());

      result.test_throws("from_string throws on unknown scheme", [] { Sig::from_string("bogus"); });
      result.test_throws("from_string throws on invalid hex 1", [] { Sig::from_string("0xZZZZ"); });
      result.test_throws("from_string throws on invalid hex 2", [] { Sig::from_string("0x03g0"); });
      result.test_throws("from_string throws on invalid hex 3", [] { Sig::from_string("0xabc"); });
   }));

   return results;
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls", "tls_signature_scheme", test_signature_scheme);

}  // namespace Botan_Tests

#endif  // BOTAN_HAS_TLS
