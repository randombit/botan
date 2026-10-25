/*
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS)
   #include <botan/tls_signature_scheme.h>
   #include <botan/tls_version.h>
#endif

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_ECDSA)
   #include <botan/ec_group.h>
   #include <botan/ecdsa.h>
   #include <botan/rng.h>
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

   results.push_back(CHECK("protocol version compatibility", [&](auto& result) {
      using Sig = Botan::TLS::Signature_Scheme;
      using PV = Botan::TLS::Version_Code;

      for(const Sig scheme : {Sig::ECDSA_BRAINPOOL256R1_TLS13_SHA256,
                              Sig::ECDSA_BRAINPOOL384R1_TLS13_SHA384,
                              Sig::ECDSA_BRAINPOOL512R1_TLS13_SHA512}) {
         result.test_is_true(scheme.to_string() + " in TLS 1.3", scheme.is_compatible_with(PV::TLS_V13));
         result.test_is_false(scheme.to_string() + " in TLS 1.2", scheme.is_compatible_with(PV::TLS_V12));
         result.test_is_false(scheme.to_string() + " in DTLS 1.2", scheme.is_compatible_with(PV::DTLS_V12));
      }

      for(const Sig scheme : {Sig::ECDSA_SHA256, Sig::ECDSA_SHA384, Sig::ECDSA_SHA512, Sig::RSA_PSS_SHA256}) {
         result.test_is_true(scheme.to_string() + " in TLS 1.3", scheme.is_compatible_with(PV::TLS_V13));
         result.test_is_true(scheme.to_string() + " in TLS 1.2", scheme.is_compatible_with(PV::TLS_V12));
      }
   }));

   #if defined(BOTAN_HAS_ECDSA)
   if(Botan::EC_Group::supports_named_group("brainpool256r1") && Botan::EC_Group::supports_named_group("secp256r1")) {
      results.push_back(CHECK("ECDSA schemes are bound to their curve", [&](auto& result) {
         using Sig = Botan::TLS::Signature_Scheme;
         auto rng = Test::new_rng("tls_signature_scheme");

         const Botan::ECDSA_PrivateKey bp256(*rng, Botan::EC_Group::from_name("brainpool256r1"));
         const Botan::ECDSA_PrivateKey p256(*rng, Botan::EC_Group::from_name("secp256r1"));

         const Sig bp_scheme = Sig::ECDSA_BRAINPOOL256R1_TLS13_SHA256;
         const Sig p256_scheme = Sig::ECDSA_SECP256R1_TLS13_SHA256;

         result.test_is_true("brainpool256r1 key with brainpool scheme", bp_scheme.is_suitable_for(bp256));
         result.test_is_false("brainpool256r1 key with secp256r1 scheme", p256_scheme.is_suitable_for(bp256));
         result.test_is_true("secp256r1 key with secp256r1 scheme", p256_scheme.is_suitable_for(p256));
         result.test_is_false("secp256r1 key with brainpool scheme", bp_scheme.is_suitable_for(p256));
         result.test_is_false("secp256r1 key with secp384r1 scheme",
                              Sig(Sig::ECDSA_SECP384R1_TLS13_SHA384).is_suitable_for(p256));

         // The curve is what matters, not how the key encodes it
         Botan::ECDSA_PrivateKey p256_explicit(*rng, Botan::EC_Group::from_name("secp256r1"));
         BOTAN_DIAGNOSTIC_PUSH
         BOTAN_DIAGNOSTIC_IGNORE_DEPRECATED_DECLARATIONS
         p256_explicit.set_parameter_encoding(Botan::EC_Group_Encoding::Explicit);
         BOTAN_DIAGNOSTIC_POP
         result.test_is_true("explicitly encoded secp256r1 key with secp256r1 scheme",
                             p256_scheme.is_suitable_for(p256_explicit));
         result.test_is_false("explicitly encoded secp256r1 key with brainpool scheme",
                              bp_scheme.is_suitable_for(p256_explicit));
      }));
   }
   #endif

   return results;
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls", "tls_signature_scheme", test_signature_scheme);

}  // namespace Botan_Tests

#endif  // BOTAN_HAS_TLS
