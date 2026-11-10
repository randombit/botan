/*
* (C) 2026 René Meusel - Rohde & Schwarz Networks and Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_13)

   #include <botan/exceptn.h>
   #include <botan/internal/stl_util.h>
   #include <botan/internal/tls_types_13.h>
   #include <limits>

using namespace Botan::TLS;

namespace Botan_Tests {

namespace {

std::vector<Test::Result> test_epoch_number_factories() {
   return {
      CHECK("unprotected epoch",
            [](Test::Result& result) {
               const auto epoch = EpochNumber::unprotected();
               result.test_u64_eq("epoch index", epoch.index(), 0);
            }),

      CHECK("early traffic epoch",
            [](Test::Result& result) {
               const auto epoch = EpochNumber::early_traffic();
               result.test_u64_eq("epoch index", epoch.index(), 1);
            }),

      CHECK("handshake traffic epoch",
            [](Test::Result& result) {
               const auto epoch = EpochNumber::handshake_traffic();
               result.test_u64_eq("epoch index", epoch.index(), 2);
            }),

      CHECK("arbitrary epoch",
            [](Test::Result& result) {
               result.test_u64_eq("first application traffic epoch", EpochNumber::create(3).index(), 3);
               result.test_u64_eq("some application traffic epoch", EpochNumber::create(1234).index(), 1234);
            }),
   };
}

std::vector<Test::Result> test_epoch_number_predicates() {
   return {
      CHECK("unprotected epoch predicates",
            [](Test::Result& result) {
               const auto epoch = EpochNumber::unprotected();
               result.test_is_true("is unprotected", epoch.is_unprotected());
               result.test_is_false("is not protected", epoch.is_protected());
               result.test_is_false("is not early traffic", epoch.is_early_traffic());
               result.test_is_false("is not handshake traffic", epoch.is_handshake_traffic());
               result.test_is_false("is not application traffic", epoch.is_application_traffic());
            }),

      CHECK("early traffic epoch predicates",
            [](Test::Result& result) {
               const auto epoch = EpochNumber::early_traffic();
               result.test_is_false("is not unprotected", epoch.is_unprotected());
               result.test_is_true("is protected", epoch.is_protected());
               result.test_is_true("is early traffic", epoch.is_early_traffic());
               result.test_is_false("is not handshake traffic", epoch.is_handshake_traffic());
               result.test_is_false("is not application traffic", epoch.is_application_traffic());
            }),

      CHECK("handshake traffic epoch predicates",
            [](Test::Result& result) {
               const auto epoch = EpochNumber::handshake_traffic();
               result.test_is_false("is not unprotected", epoch.is_unprotected());
               result.test_is_true("is protected", epoch.is_protected());
               result.test_is_false("is not early traffic", epoch.is_early_traffic());
               result.test_is_true("is handshake traffic", epoch.is_handshake_traffic());
               result.test_is_false("is not application traffic", epoch.is_application_traffic());
            }),

      CHECK("first application traffic epoch predicates",
            [](Test::Result& result) {
               const auto epoch = EpochNumber::create(3);
               result.test_is_false("is not unprotected", epoch.is_unprotected());
               result.test_is_true("is protected", epoch.is_protected());
               result.test_is_false("is not early traffic", epoch.is_early_traffic());
               result.test_is_false("is not handshake traffic", epoch.is_handshake_traffic());
               result.test_is_true("is application traffic", epoch.is_application_traffic());
            }),

      CHECK("later application traffic epoch predicates",
            [](Test::Result& result) {
               const auto epoch = EpochNumber::create(42);
               result.test_is_false("is not unprotected", epoch.is_unprotected());
               result.test_is_true("is protected", epoch.is_protected());
               result.test_is_false("is not early traffic", epoch.is_early_traffic());
               result.test_is_false("is not handshake traffic", epoch.is_handshake_traffic());
               result.test_is_true("is application traffic", epoch.is_application_traffic());
            }),
   };
}

std::vector<Test::Result> test_epoch_number_application_traffic_index() {
   return {
      CHECK("non-application epochs have no application traffic index",
            [](Test::Result& result) {
               result.test_opt_u64_eq(
                  "unprotected", EpochNumber::unprotected().application_traffic_index(), std::nullopt);
               result.test_opt_u64_eq(
                  "early traffic", EpochNumber::early_traffic().application_traffic_index(), std::nullopt);
               result.test_opt_u64_eq(
                  "handshake traffic", EpochNumber::handshake_traffic().application_traffic_index(), std::nullopt);
            }),

      CHECK("application epochs count from zero",
            [](Test::Result& result) {
               result.test_opt_u64_eq("first application traffic epoch",
                                      EpochNumber::create(3).application_traffic_index(),
                                      std::optional<uint64_t>(0));
               result.test_opt_u64_eq("some application traffic epoch",
                                      EpochNumber::create(1234).application_traffic_index(),
                                      std::optional<uint64_t>(1231));
            }),
   };
}

std::vector<Test::Result> test_epoch_number_next() {
   return {
      CHECK("next epoch",
            [](Test::Result& result) {
               result.test_u64_eq("next of unprotected", EpochNumber::unprotected().next().index(), 1);
               result.test_u64_eq("next of early traffic", EpochNumber::early_traffic().next().index(), 2);
               result.test_u64_eq("next of handshake traffic", EpochNumber::handshake_traffic().next().index(), 3);
               result.test_u64_eq("next of an application traffic epoch", EpochNumber::create(42).next().index(), 43);
            }),

      CHECK("chained next epoch",
            [](Test::Result& result) {
               const auto epoch = EpochNumber::unprotected().next().next().next();
               result.test_u64_eq("advanced thrice", epoch.index(), 3);
            }),

      CHECK("next epoch is rejected on exhaustion",
            [](Test::Result& result) {
               result.test_throws<Botan::Invalid_State>("cannot advance the maximal epoch", [&] {
                  std::ignore = EpochNumber::create(std::numeric_limits<EpochNumber::value_type>::max()).next();
               });
            }),
   };
}

std::vector<Test::Result> test_epoch_number_comparison() {
   return {
      CHECK("equality comparison",
            [](Test::Result& result) {
               result.test_is_true("equal epochs", EpochNumber::unprotected() == EpochNumber::create(0));
               result.test_is_true("unequal epochs", EpochNumber::unprotected() != EpochNumber::unprotected().next());
            }),

      CHECK("ordering comparison",
            [](Test::Result& result) {
               result.test_is_true("unprotected < early traffic",
                                   EpochNumber::unprotected() < EpochNumber::early_traffic());
               result.test_is_true("early traffic < handshake traffic",
                                   EpochNumber::early_traffic() < EpochNumber::handshake_traffic());
               result.test_is_true("handshake traffic < application traffic",
                                   EpochNumber::handshake_traffic() < EpochNumber::create(3));
               result.test_is_true("application traffic epochs order by index",
                                   EpochNumber::create(3) < EpochNumber::create(4));
               result.test_is_true("epoch is not greater than itself",
                                   !(EpochNumber::unprotected() > EpochNumber::create(0)));
            }),
   };
}

std::vector<Test::Result> test_epoch_number_dtls_exhaustion() {
   return {
      CHECK("early epochs are not exhausted for DTLS",
            [](Test::Result& result) {
               result.test_is_false("unprotected", EpochNumber::unprotected().is_exhausted_for_dtls());
               result.test_is_false("early traffic", EpochNumber::early_traffic().is_exhausted_for_dtls());
               result.test_is_false("handshake traffic", EpochNumber::handshake_traffic().is_exhausted_for_dtls());
               result.test_is_false("first application traffic", EpochNumber::create(3).is_exhausted_for_dtls());
            }),

      CHECK("high epochs are not exhausted for DTLS",
            [](Test::Result& result) {
               // RFC 9147 8. (Errata-ID 8050) allows epochs up to 2^16-2
               result.test_is_false("largest allowed epoch", EpochNumber::create(0xFFFE).is_exhausted_for_dtls());
            }),

      CHECK("extreme epochs are exhausted for DTLS",
            [](Test::Result& result) {
               result.test_is_true("2^16-1 is exhausted", EpochNumber::create(0xFFFF).is_exhausted_for_dtls());
               result.test_is_true("beyond 2^16-1 is exhausted", EpochNumber::create(0x10000).is_exhausted_for_dtls());
               result.test_is_true(
                  "maximal epoch is exhausted",
                  EpochNumber::create(std::numeric_limits<EpochNumber::value_type>::max()).is_exhausted_for_dtls());
            }),
   };
}

BOTAN_REGISTER_TEST_FN("tls",
                       "tls_epoch_number",
                       test_epoch_number_factories,
                       test_epoch_number_predicates,
                       test_epoch_number_application_traffic_index,
                       test_epoch_number_next,
                       test_epoch_number_comparison,
                       test_epoch_number_dtls_exhaustion);

}  // namespace

}  // namespace Botan_Tests

#endif
