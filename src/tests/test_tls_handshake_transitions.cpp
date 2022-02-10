/*
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS)

#include <botan/internal/tls_handshake_transitions.h>

using namespace Botan::TLS;
using namespace Botan_Tests;

namespace {

template<typename FunT>
Test::Result CHECK(const char* name, FunT check_fun)
   {
   Botan_Tests::Test::Result r(name);
   try
      {
      check_fun(r);
      }
   catch(const Botan_Tests::Test_Aborted&)
      {
      // pass, failure was already noted in the responsible `require`
      }
   catch(const std::exception& ex)
      {
      r.test_failure(std::string("failed with exception: ") + ex.what());
      }
   return r;
   }

std::vector<Test::Result> test_handshake_state_transitions()
   {
   return {
      CHECK("uninitialized expects nothing", [](Test::Result& result) {
         Handshake_Transitions ht;
         result.confirm("CCS is not expected by default", !ht.change_cipher_spec_expected());

         result.confirm("no messages were received", !ht.received_handshake_msg(Handshake_Type::CLIENT_HELLO));
         result.test_throws("no expectations set, always throws", [&] {
            ht.confirm_transition_to(Handshake_Type::CLIENT_HELLO);
         });
      }),

      CHECK("expect exactly one message", [](Test::Result& result) {
         Handshake_Transitions ht;
         ht.set_expected_next(Handshake_Type::CLIENT_HELLO);

         result.test_no_throw("client hello met expectation", [&] {
            ht.confirm_transition_to(Handshake_Type::CLIENT_HELLO);
         });

         result.confirm("received client hello", ht.received_handshake_msg(Handshake_Type::CLIENT_HELLO));

         result.test_throws("confirmation resets expectations", [&] {
            ht.confirm_transition_to(Handshake_Type::CLIENT_HELLO);
         });
      }),

      CHECK("expect exactly one message but don't satisfy it", [](Test::Result& result)
         {
         Handshake_Transitions ht;
         ht.set_expected_next(Handshake_Type::CLIENT_HELLO);

         result.test_throws("server hello does not meet expectation", [&]{
            ht.confirm_transition_to(Handshake_Type::SERVER_HELLO);
         });
         }),

      CHECK("two expectations can be fulfilled", [](Test::Result& result)
         {
         Handshake_Transitions ht;
         ht.set_expected_next({Handshake_Type::CERTIFICATE_REQUEST,Handshake_Type::CERTIFICATE});

         auto ht2 = ht;  // copying, as confirmation reset the object's superposition

         result.test_no_throw("CERTIFICATE", [&] {
            ht.confirm_transition_to(Handshake_Type::CERTIFICATE);
         });
         result.confirm("received CERTIFICATE", ht.received_handshake_msg(Handshake_Type::CERTIFICATE));

         result.test_no_throw("CERTIFICATE_REQUEST", [&] {
            ht2.confirm_transition_to(Handshake_Type::CERTIFICATE_REQUEST);
         });
         result.confirm("received CERTIFICATE_REQUEST", ht2.received_handshake_msg(Handshake_Type::CERTIFICATE_REQUEST));
         }),

      CHECK("expect CCS", [](Test::Result& result)
         {
         Handshake_Transitions ht;
         ht.set_expected_next(Handshake_Type::HANDSHAKE_CCS);
         result.confirm("CCS expected", ht.change_cipher_spec_expected());
         }),
      };
   }

}  // namespace

namespace Botan_Tests {
BOTAN_REGISTER_TEST_FN("tls", "tls_handshake_transitions",
                       test_handshake_state_transitions);
}

#endif
