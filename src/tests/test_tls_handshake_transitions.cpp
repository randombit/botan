/*
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS)

   #include <botan/internal/tls_handshake_transitions.h>

namespace Botan_Tests {

namespace {

std::vector<Test::Result> test_handshake_state_transitions() {
   return {
      CHECK("uninitialized expects nothing",
            [](Test::Result& result) {
               Botan::TLS::Handshake_Transitions ht;
               result.confirm("CCS is not expected by default", !ht.change_cipher_spec_expected());

               result.confirm("no messages were received",
                              !ht.received_handshake_msg(Botan::TLS::Handshake_Type::ClientHello));
               result.test_throws("no expectations set, always throws",
                                  [&] { ht.confirm_transition_to(Botan::TLS::Handshake_Type::ClientHello); });
            }),

      CHECK("expect exactly one message",
            [](Test::Result& result) {
               Botan::TLS::Handshake_Transitions ht;
               ht.set_expected_next(Botan::TLS::Handshake_Type::ClientHello);

               result.test_no_throw("client hello met expectation",
                                    [&] { ht.confirm_transition_to(Botan::TLS::Handshake_Type::ClientHello); });

               result.confirm("received client hello",
                              ht.received_handshake_msg(Botan::TLS::Handshake_Type::ClientHello));

               result.test_throws("confirmation resets expectations",
                                  [&] { ht.confirm_transition_to(Botan::TLS::Handshake_Type::ClientHello); });
            }),

      CHECK("expect exactly one message but don't satisfy it",
            [](Test::Result& result) {
               Botan::TLS::Handshake_Transitions ht;
               ht.set_expected_next(Botan::TLS::Handshake_Type::ClientHello);

               result.test_throws("server hello does not meet expectation",
                                  [&] { ht.confirm_transition_to(Botan::TLS::Handshake_Type::ServerHello); });
            }),

      CHECK("two expectations can be fulfilled",
            [](Test::Result& result) {
               Botan::TLS::Handshake_Transitions ht;
               ht.set_expected_next(
                  {Botan::TLS::Handshake_Type::CertificateRequest, Botan::TLS::Handshake_Type::Certificate});

               auto ht2 = ht;  // copying, as confirmation reset the object's superposition

               result.test_no_throw("CERTIFICATE",
                                    [&] { ht.confirm_transition_to(Botan::TLS::Handshake_Type::Certificate); });
               result.confirm("received CERTIFICATE",
                              ht.received_handshake_msg(Botan::TLS::Handshake_Type::Certificate));

               result.test_no_throw("CERTIFICATE_REQUEST",
                                    [&] { ht2.confirm_transition_to(Botan::TLS::Handshake_Type::CertificateRequest); });
               result.confirm("received CERTIFICATE_REQUEST",
                              ht2.received_handshake_msg(Botan::TLS::Handshake_Type::CertificateRequest));
            }),

      CHECK("expect CCS",
            [](Test::Result& result) {
               Botan::TLS::Handshake_Transitions ht;
               ht.set_expected_next(Botan::TLS::Handshake_Type::HandshakeCCS);
               result.confirm("CCS expected", ht.change_cipher_spec_expected());
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls", "tls_handshake_transitions", test_handshake_state_transitions);
}  // namespace Botan_Tests

#endif
