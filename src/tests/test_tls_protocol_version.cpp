/*
* (C) 2026 Jack Lloyd
*     2026 René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS)

   #include <botan/tls_version.h>

namespace Botan_Tests {

namespace {

namespace TLS = Botan::TLS;

TLS::Protocol_Version latest_tls_version_in_this_build() {
   #if defined(BOTAN_HAS_TLS_13)
   return TLS::Protocol_Version::TLS_V13;
   #elif defined(BOTAN_HAS_TLS_12)
   return TLS::Protocol_Version::TLS_V12;
   #else
   static_assert(false, "No TLS in this build, some #ifdef issue in the test code?");
   #endif
}

TLS::Protocol_Version latest_dtls_version_in_this_build() {
   #if defined(BOTAN_HAS_TLS_12)
   return TLS::Protocol_Version::DTLS_V12;
   #else
   static_assert(false, "No DTLS in this build, some #ifdef issue in the test code?");
   #endif
}

std::vector<Test::Result> tls_protocol_version_wrapper() {
   return {
      CHECK("protocol version factories",
            [&](Test::Result& result) {
               result.test_is_true("latest_tls_version() returns correct version",
                                   TLS::Protocol_Version::latest_tls_version() == latest_tls_version_in_this_build());
               result.test_is_true("latest_dtls_version() returns correct version",
                                   TLS::Protocol_Version::latest_dtls_version() == latest_dtls_version_in_this_build());
            }),

      CHECK("default constructor",
            [&](Test::Result& result) {
               const TLS::Protocol_Version v;
               result.test_is_true("returns invalid version", !v.valid());
               result.test_is_true("returns unknown version", !v.known_version());
            }),

      CHECK("concrete constructors",
            [&](Test::Result& result) {
               using PV = TLS::Protocol_Version;

               auto check = [&](const PV& pv, std::string_view expected) {
                  result.test_str_eq("to_string() for " + std::string(expected), pv.to_string(), expected);
               };

               check(PV(0x0301), "TLS v1.0");
               check(PV(0x0302), "TLS v1.1");
               check(PV(0x0303), "TLS v1.2");
               check(PV(0x0304), "TLS v1.3");

               check(PV(0xFEFF), "DTLS v1.0");
               check(PV(0xFEFD), "DTLS v1.2");
               check(PV(0xFEFC), "DTLS v1.3");

               check(PV(PV::TLS_V11), "TLS v1.1");
               check(PV(PV::TLS_V12), "TLS v1.2");
               check(PV(PV::TLS_V13), "TLS v1.3");

               check(PV(PV::DTLS_V10), "DTLS v1.0");
               check(PV(PV::DTLS_V12), "DTLS v1.2");
               check(PV(PV::DTLS_V13), "DTLS v1.3");

               check(PV(3, 0), "SSL v3");
               check(PV(2, 0), "Unknown 2.0");
            }),

      CHECK("detect pre-TLS 1.3",
            [](Test::Result& result) {
               using PV = TLS::Protocol_Version;

               result.test_is_true("TLS v1.1 is pre-TLS 1.3", PV(PV::TLS_V11).is_pre_tls_13());
               result.test_is_true("TLS v1.2 is pre-TLS 1.3", PV(PV::TLS_V12).is_pre_tls_13());
               result.test_is_true("TLS v1.3 is not pre-TLS 1.3", !PV(PV::TLS_V13).is_pre_tls_13());
               result.test_is_true("(hypothetical) TLS v1.4 is not pre-TLS 1.3", !PV(0x0305).is_pre_tls_13());

               result.test_is_true("DTLS v1.0 is pre-TLS 1.3", PV(PV::DTLS_V10).is_pre_tls_13());
               result.test_is_true("DTLS v1.2 is pre-TLS 1.3", PV(PV::DTLS_V12).is_pre_tls_13());
               result.test_is_true("DTLS v1.2 is pre-TLS 1.3", PV(PV::DTLS_V12).is_pre_tls_13());
               result.test_is_true("DTLS v1.3 is not pre-TLS 1.3", !PV(PV::DTLS_V13).is_pre_tls_13());
               result.test_is_true("(hypothetical) DTLS v1.4 is not pre-TLS 1.3", !PV(0xFEFB).is_pre_tls_13());
            }),

      CHECK("detect TLS 1.3 or later",
            [](Test::Result& result) {
               using PV = TLS::Protocol_Version;

               result.test_is_true("TLS v1.1 is not TLS 1.3 or later", !PV(PV::TLS_V11).is_tls_13_or_later());
               result.test_is_true("TLS v1.2 is not TLS 1.3 or later", !PV(PV::TLS_V12).is_tls_13_or_later());
               result.test_is_true("TLS v1.3 is TLS 1.3 or later", PV(PV::TLS_V13).is_tls_13_or_later());
               result.test_is_true("(hypothetical) TLS v1.4 is TLS 1.3 or later", PV(0x0305).is_tls_13_or_later());

               result.test_is_true("DTLS v1.0 is not TLS 1.3 or later", !PV(PV::DTLS_V10).is_tls_13_or_later());
               result.test_is_true("DTLS v1.2 is not TLS 1.3 or later", !PV(PV::DTLS_V12).is_tls_13_or_later());
               result.test_is_true("DTLS v1.3 is TLS 1.3 or later", PV(PV::DTLS_V13).is_tls_13_or_later());
               result.test_is_true("(hypothetical) DTLS v1.4 is TLS 1.3 or later", PV(0xFEFB).is_tls_13_or_later());
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls", "tls_protocol_version", tls_protocol_version_wrapper);

}  // namespace Botan_Tests

#endif
