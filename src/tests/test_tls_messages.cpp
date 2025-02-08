/*
* (C) 2016 Juraj Somorovsky
* (C) 2021 Elektrobit Automotive GmbH
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio GmbH
* (C) 2022 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS)
   #include <botan/hex.h>
   #include <botan/mac.h>
   #include <botan/ocsp.h>
   #include <botan/tls_alert.h>
   #include <botan/tls_callbacks.h>
   #include <botan/tls_ciphersuite.h>
   #include <botan/tls_handshake_msg.h>
   #include <botan/tls_messages.h>
   #include <botan/tls_version.h>
   #include <botan/internal/loadstor.h>
   #include <algorithm>
   #include <exception>

   #if defined(BOTAN_HAS_TLS_13)
      #include "test_rng.h"
      #include <botan/internal/tls_reader.h>
   #endif
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_TLS)
Test::Result test_hello_verify_request() {
   Test::Result result("hello_verify_request construction");

   std::vector<uint8_t> test_data;
   std::vector<uint8_t> key_data(32);
   Botan::SymmetricKey sk(key_data);

   // Compute cookie over an empty string with an empty test data
   Botan::TLS::Hello_Verify_Request hfr(test_data, "", sk);

   // Compute HMAC
   auto hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
   hmac->set_key(sk);
   hmac->update_be(uint64_t(0));  // length of client hello
   hmac->update_be(uint64_t(0));  // length of client identity
   std::vector<uint8_t> test = unlock(hmac->final());

   result.test_eq("Cookie comparison", hfr.cookie(), test);
   return result;
}

class Test_Callbacks : public Botan::TLS::Callbacks {
   public:
      Test_Callbacks(Test::Result& result) : m_result(result) {}

   public:
      void tls_emit_data(std::span<const uint8_t>) override {
         m_result.test_failure("unsolicited call to tls_emit_data");
      }

      void tls_record_received(uint64_t, std::span<const uint8_t>) override {
         m_result.test_failure("unsolicited call to tls_record_received");
      }

      void tls_alert(Botan::TLS::Alert) override { m_result.test_failure("unsolicited call to tls_alert"); }

      void tls_session_established(const Botan::TLS::Session_Summary&) override {
         m_result.test_failure("unsolicited call to tls_session_established");
      }

   private:
      Test::Result& m_result;
};

class TLS_Message_Parsing_Test final : public Text_Based_Test {
   public:
      TLS_Message_Parsing_Test() :
            Text_Based_Test("tls", "Buffer,Exception", "Protocol,AdditionalData,Ciphersuite,Name") {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override {
         const std::vector<uint8_t> buffer = vars.get_req_bin("Buffer");
         const std::vector<uint8_t> protocol = vars.get_opt_bin("Protocol");
         const std::vector<uint8_t> ciphersuite = vars.get_opt_bin("Ciphersuite");
         const std::string exception = vars.get_req_str("Exception");
         const std::string expected_name = vars.get_opt_str("Name", "");
         const bool is_positive_test = exception.empty();

         Test::Result result(algo + " parsing");

         if(is_positive_test) {
            try {
               if(algo == "cert_verify") {
                  Botan::TLS::Certificate_Verify message(buffer);
               } else if(algo == "client_hello") {
                  const std::string extensions = vars.get_req_str("AdditionalData");
                  Botan::TLS::Protocol_Version pv(protocol[0], protocol[1]);
                  Botan::TLS::Client_Hello_12 message(buffer);
                  result.test_eq("Protocol version", message.legacy_version().to_string(), pv.to_string());
                  std::vector<uint8_t> buf;
                  for(const Botan::TLS::Extension_Code& type : message.extension_types()) {
                     uint16_t u16type = static_cast<uint16_t>(type);
                     buf.push_back(Botan::get_byte<0>(u16type));
                     buf.push_back(Botan::get_byte<1>(u16type));
                  }
                  result.test_eq("Hello extensions", Botan::hex_encode(buf), extensions);
               } else if(algo == "hello_verify") {
                  Botan::TLS::Hello_Verify_Request message(buffer);
               } else if(algo == "hello_request") {
                  Botan::TLS::Hello_Request message(buffer);
               } else if(algo == "new_session_ticket") {
                  Botan::TLS::New_Session_Ticket_12 message(buffer);
               } else if(algo == "server_hello") {
                  const std::string extensions = vars.get_req_str("AdditionalData");
                  Botan::TLS::Protocol_Version pv(protocol[0], protocol[1]);
                  Botan::TLS::Ciphersuite cs =
                     Botan::TLS::Ciphersuite::by_id(Botan::make_uint16(ciphersuite[0], ciphersuite[1])).value();
                  Botan::TLS::Server_Hello_12 message(buffer);
                  result.test_eq("Protocol version", message.legacy_version().to_string(), pv.to_string());
                  result.confirm("Ciphersuite", (message.ciphersuite() == cs.ciphersuite_code()));
                  std::vector<uint8_t> buf;
                  for(const Botan::TLS::Extension_Code& type : message.extension_types()) {
                     uint16_t u16type = static_cast<uint16_t>(type);
                     buf.push_back(Botan::get_byte<0>(u16type));
                     buf.push_back(Botan::get_byte<1>(u16type));
                  }
                  result.test_eq("Hello extensions", Botan::hex_encode(buf), extensions);
               } else if(algo == "alert") {
                  Botan::secure_vector<uint8_t> sb(buffer.begin(), buffer.end());
                  Botan::TLS::Alert message(sb);
                  result.test_lt("Alert type vectors result to UNKNOWN_CA or ACCESS_DENIED, which is shorter than 15",
                                 message.type_string().size(),
                                 15);
               } else if(algo == "cert_status") {
                  Botan::TLS::Certificate_Status message(buffer, Botan::TLS::Connection_Side::Server);

                  Botan::OCSP::Response resp(message.response());

                  const std::vector<std::string> CNs = resp.signer_name().get_attribute("CN");

                  // This is not requird by OCSP protocol, we are just using it as a test here
                  if(result.test_eq("OCSP response has signer name", CNs.size(), 1)) {
                     result.test_eq("Expected name", CNs[0], expected_name);
                  }
               } else {
                  throw Test_Error("Unknown message type " + algo + " in TLS parsing tests");
               }
               result.test_success("Correct parsing");
            } catch(std::exception& e) {
               result.test_failure(e.what());
            }
         } else {
            if(algo == "cert_verify") {
               result.test_throws("invalid cert_verify input", exception, [&buffer]() {
                  Botan::TLS::Certificate_Verify message(buffer);
               });
            } else if(algo == "client_hello") {
               result.test_throws("invalid client_hello input", exception, [&buffer]() {
                  Botan::TLS::Client_Hello_12 message(buffer);
               });
            } else if(algo == "hello_verify") {
               result.test_throws("invalid hello_verify input", exception, [&buffer]() {
                  Botan::TLS::Hello_Verify_Request message(buffer);
               });
            } else if(algo == "hello_request") {
               result.test_throws(
                  "invalid hello_request input", exception, [&buffer]() { Botan::TLS::Hello_Request message(buffer); });
            } else if(algo == "cert_status") {
               result.test_throws("invalid cert_status input", exception, [&buffer]() {
                  Botan::TLS::Certificate_Status message(buffer, Botan::TLS::Connection_Side::Server);
               });
            } else if(algo == "new_session_ticket") {
               result.test_throws("invalid new_session_ticket input", exception, [&buffer]() {
                  Botan::TLS::New_Session_Ticket_12 message(buffer);
               });
            } else if(algo == "server_hello") {
               result.test_throws("invalid server_hello input", exception, [&buffer]() {
                  Botan::TLS::Server_Hello_12 message(buffer);
               });
            } else if(algo == "alert") {
               result.test_throws("invalid alert input", exception, [&buffer]() {
                  Botan::secure_vector<uint8_t> sb(buffer.begin(), buffer.end());
                  Botan::TLS::Alert message(sb);
               });
            } else {
               throw Test_Error("Unknown message type " + algo + " in TLS parsing tests");
            }
         }

         return result;
      }

      std::vector<Test::Result> run_final_tests() override {
         std::vector<Test::Result> results;

         results.push_back(test_hello_verify_request());

         return results;
      }
};

BOTAN_REGISTER_TEST("tls", "tls_messages", TLS_Message_Parsing_Test);

   #if defined(BOTAN_HAS_TLS_13)
      #if defined(BOTAN_HAS_X25519)
class TLS_Key_Share_CH_Generation_Test final : public Text_Based_Test {
   public:
      TLS_Key_Share_CH_Generation_Test() :
            Text_Based_Test("tls_extensions/generation/key_share_CH_offers.vec",
                            "Groups,Rng_Data,Expected_Content",
                            "Offered_Groups") {}

      Test::Result run_one_test(const std::string& extension, const VarMap& vars) override {
         Test::Result result(extension + " generation");

         const auto rng_data = vars.get_req_bin("Rng_Data");
         const auto groups = vars.get_req_str("Groups");
         const auto offered_groups = vars.get_opt_str("Offered_Groups", groups);
         const auto expected_key_share = vars.get_req_bin("Expected_Content");

         Test_Callbacks cb(result);
         Botan::TLS::Text_Policy policy("key_exchange_groups = " + groups +
                                        "\n"
                                        "key_exchange_groups_to_offer = " +
                                        offered_groups);
         Fixed_Output_RNG rng;
         rng.add_entropy(rng_data.data(), rng_data.size());

         Botan::TLS::Key_Share share(policy, cb, rng);
         const auto serialized_buffer = share.serialize(Botan::TLS::Connection_Side::Client);

         result.test_eq("key_share_CH_offers test", serialized_buffer, expected_key_share);

         return result;
      }
};

BOTAN_REGISTER_TEST("tls_extensions", "tls_extensions_key_share_client_hello", TLS_Key_Share_CH_Generation_Test);

      #endif

class TLS_Extension_Parsing_Test final : public Text_Based_Test {
   public:
      TLS_Extension_Parsing_Test() :
            Text_Based_Test("tls_extensions/parsing",
                            "Buffer,Exception",
                            "Protocol,Ciphersuite,AdditionalData,Name,Expected_Content") {}

      Test::Result run_one_test(const std::string& extension, const VarMap& vars) override {
         const std::vector<uint8_t> buffer = vars.get_req_bin("Buffer");
         const std::vector<uint8_t> protocol = vars.get_opt_bin("Protocol");
         const std::vector<uint8_t> ciphersuite = vars.get_opt_bin("Ciphersuite");
         const std::string exception = vars.get_req_str("Exception");
         const bool is_positive_test = exception.empty();

         Test::Result result(extension + " parsing");

         if(is_positive_test) {
            try {
               if(extension == "supported_version") {
                  const std::string expected_buffer = Botan::hex_encode(buffer);
                  Botan::TLS::TLS_Data_Reader tls_data_reader("ClientHello", buffer);
                  Botan::TLS::Supported_Versions supported_versions(
                     tls_data_reader, static_cast<uint16_t>(buffer.size()), Botan::TLS::Connection_Side::Client);
                  const auto serialized_buffer = supported_versions.serialize(Botan::TLS::Connection_Side::Client);

                  const std::vector<std::vector<uint8_t>> expected_versions = vars.get_req_bin_list("Expected_Content");
                  for(const auto& expected_version : expected_versions) {
                     result.confirm("Expected_Content",
                                    supported_versions.supports(
                                       Botan::TLS::Protocol_Version(expected_version[0], expected_version[1])));
                  }

                  result.test_eq("supported_version test 1", Botan::hex_encode(serialized_buffer), expected_buffer);
               } else if(extension == "supported_groups") {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("ClientHello", buffer);
                  Botan::TLS::Supported_Groups supp_groups_ext(tls_data_reader, static_cast<uint16_t>(buffer.size()));

                  const auto serialized_buffer = supp_groups_ext.serialize(Botan::TLS::Connection_Side::Client);
                  const auto expected_content = vars.get_req_bin("Expected_Content");

                  const auto dh_groups = supp_groups_ext.dh_groups();
                  const auto ec_groups = supp_groups_ext.ec_groups();

                  std::vector<Botan::TLS::Named_Group> named_groupes;
                  std::merge(dh_groups.begin(),
                             dh_groups.end(),
                             ec_groups.begin(),
                             ec_groups.end(),
                             std::back_inserter(named_groupes));

                  result.confirm("supported_groups extension - size check",
                                 (named_groupes.size() * 2) == expected_content.size());

                  for(size_t i = 0; i < expected_content.size(); i += 2) {
                     const auto expected_named_group =
                        Botan::make_uint16(expected_content.at(i), expected_content.at(i + 1));

                     result.confirm("signature_algorithms_cert extension - named group check",
                                    std::any_of(named_groupes.cbegin(),
                                                named_groupes.cend(),
                                                [&expected_named_group](const Botan::TLS::Named_Group& named_group) {
                                                   return static_cast<Botan::TLS::Named_Group>(expected_named_group) ==
                                                          named_group;
                                                }));
                  }

                  result.test_eq("supported_groups extension - serialization test", serialized_buffer, buffer);
               } else if(extension == "signature_algorithms_cert") {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("ClientHello", buffer);
                  Botan::TLS::Signature_Algorithms_Cert sig_algo_cert(tls_data_reader,
                                                                      static_cast<uint16_t>(buffer.size()));

                  const auto serialized_buffer = sig_algo_cert.serialize(Botan::TLS::Connection_Side::Client);
                  const auto expected_content = vars.get_req_bin("Expected_Content");

                  result.confirm("signature_algorithms_cert extension - size check",
                                 sig_algo_cert.supported_schemes().size() * 2 == expected_content.size());

                  size_t offset = 0;
                  for(const auto& sig_scheme : sig_algo_cert.supported_schemes()) {
                     const auto expected_sig_scheme =
                        Botan::make_uint16(expected_content.at(offset), expected_content.at(offset + 1));

                     result.confirm("signature_algorithms_cert extension - sig scheme check",
                                    Botan::TLS::Signature_Scheme(expected_sig_scheme) == sig_scheme);

                     offset += 2;
                  }

                  result.test_eq("signature_algorithms_cert extension - serialization test", serialized_buffer, buffer);
               } else if(extension == "cookie") {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("HelloRetryRequest", buffer);
                  Botan::TLS::Cookie cookie(tls_data_reader, static_cast<uint16_t>(buffer.size()));

                  const auto serialized_buffer = cookie.serialize(Botan::TLS::Connection_Side::Server);
                  const auto expected_cookie = vars.get_req_bin("Expected_Content");

                  result.test_eq("Cookie extension test",
                                 Botan::hex_encode(expected_cookie),
                                 Botan::hex_encode(cookie.get_cookie()));
               } else if(extension == "key_share_HRR") {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("HelloRetryRequest", buffer);
                  Botan::TLS::Key_Share key_share(tls_data_reader,
                                                  static_cast<uint16_t>(buffer.size()),
                                                  Botan::TLS::Handshake_Type::HelloRetryRequest);

                  const auto serialized_buffer = key_share.serialize(Botan::TLS::Connection_Side::Client);
                  const auto expected_key_share = vars.get_req_bin("Expected_Content");

                  result.test_eq(
                     "key_share_HRR test", Botan::hex_encode(serialized_buffer), Botan::hex_encode(expected_key_share));
               } else if(extension == "key_share_SH") {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("ServerHello", buffer);
                  Botan::TLS::Key_Share key_share(
                     tls_data_reader, static_cast<uint16_t>(buffer.size()), Botan::TLS::Handshake_Type::ServerHello);

                  const auto serialized_buffer = key_share.serialize(Botan::TLS::Connection_Side::Client);
                  const auto expected_key_share = vars.get_req_bin("Expected_Content");

                  result.test_eq(
                     "key_share_SH test", Botan::hex_encode(serialized_buffer), Botan::hex_encode(expected_key_share));
               } else if(extension == "key_share_CH") {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("ClientHello", buffer);
                  Botan::TLS::Key_Share key_share(
                     tls_data_reader, static_cast<uint16_t>(buffer.size()), Botan::TLS::Handshake_Type::ClientHello);

                  const auto serialized_buffer = key_share.serialize(Botan::TLS::Connection_Side::Server);
                  const auto expected_key_share = vars.get_req_bin("Expected_Content");

                  result.test_eq(
                     "key_share_CH test", Botan::hex_encode(serialized_buffer), Botan::hex_encode(expected_key_share));
               } else {
                  throw Test_Error("Unknown extension type " + extension + " in TLS parsing tests");
               }
               result.test_success("Correct parsing");
            } catch(std::exception& e) {
               result.test_failure(e.what());
            }
         } else {
         }

         return result;
      }

      std::vector<Test::Result> run_final_tests() override {
         std::vector<Test::Result> results;

         results.push_back(test_hello_verify_request());

         return results;
      }
};

BOTAN_REGISTER_TEST("tls_extensions", "tls_extensions_parsing", TLS_Extension_Parsing_Test);

class TLS_13_Message_Parsing_Test final : public Text_Based_Test {
   public:
      TLS_13_Message_Parsing_Test() :
            Text_Based_Test("tls_13", "Buffer,Exception", "Protocol,Message_Type,AdditionalData,Ciphersuite,Name") {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override {
         const std::vector<uint8_t> buffer = vars.get_req_bin("Buffer");
         const std::vector<uint8_t> protocol = vars.get_opt_bin("Protocol");
         const std::string msg_type = vars.get_opt_str("Message_Type", "");
         const std::vector<uint8_t> ciphersuite = vars.get_opt_bin("Ciphersuite");
         const std::string exception = vars.get_req_str("Exception");
         const bool is_positive_test = exception.empty();

         Test::Result result("TLS 1.3 " + algo + " parsing");

         if(algo == "client_hello") {
            try {
               std::visit(
                  [&](auto ch) {
                     if constexpr(std::is_same_v<Botan::TLS::Client_Hello_12, decltype(ch)>) {
                        result.confirm("expected Client_Hello_12", msg_type == "client_hello_12");
                     }
                     if constexpr(std::is_same_v<Botan::TLS::Client_Hello_13, decltype(ch)>) {
                        result.confirm("expected Client_Hello_13", msg_type == "client_hello_13");
                     }

                     const std::string extensions = vars.get_req_str("AdditionalData");
                     std::vector<uint8_t> exts_buffer;
                     for(Botan::TLS::Extension_Code const& type : ch.extensions().extension_types()) {
                        uint16_t u16type = static_cast<uint16_t>(type);
                        exts_buffer.push_back(Botan::get_byte<0>(u16type));
                        exts_buffer.push_back(Botan::get_byte<1>(u16type));
                     }
                     result.test_eq("Hello extensions", Botan::hex_encode(exts_buffer), extensions);

                     std::vector<uint8_t> ciphersuites_buffer;
                     for(const auto& cs : ch.ciphersuites()) {
                        ciphersuites_buffer.push_back(Botan::get_byte<0>(cs));
                        ciphersuites_buffer.push_back(Botan::get_byte<1>(cs));
                     }
                     result.test_eq("Supported ciphersuites", ciphersuites_buffer, ciphersuite);

                     result.confirm("this is a positive test that should not have failed yet", is_positive_test);
                  },
                  Botan::TLS::Client_Hello_13::parse(buffer));
            } catch(const std::exception& ex) {
               result.test_eq("correct error produced", ex.what(), exception);
               result.confirm("negative test", !is_positive_test);
            }
         }

         if(algo == "server_hello") {
            const std::string extensions = vars.get_req_str("AdditionalData");
            const Botan::TLS::Ciphersuite cs =
               Botan::TLS::Ciphersuite::by_id(Botan::make_uint16(ciphersuite[0], ciphersuite[1])).value();
            const Botan::TLS::Protocol_Version pv(protocol[0], protocol[1]);

            try {
               std::visit(
                  [&](auto msg) {
                     if constexpr(std::is_same_v<Botan::TLS::Server_Hello_12, decltype(msg)>) {
                        result.confirm("expected Server_Hello_12", msg_type == "server_hello_12");
                        result.confirm("expected pre TLS 1.3 message", pv == msg.legacy_version());
                     } else if constexpr(std::is_same_v<Botan::TLS::Server_Hello_13, decltype(msg)>) {
                        result.confirm("expected Server_Hello_13", msg_type == "server_hello_13");
                     } else if constexpr(std::is_same_v<Botan::TLS::Hello_Retry_Request, decltype(msg)>) {
                        result.confirm("expected Hello_Retry_Request", msg_type == "hello_retry_request");
                     }

                     result.confirm("Ciphersuite", (msg.ciphersuite() == cs.ciphersuite_code()));

                     std::vector<uint8_t> buf;
                     for(Botan::TLS::Extension_Code const& type : msg.extensions().extension_types()) {
                        uint16_t u16type = static_cast<uint16_t>(type);
                        buf.push_back(Botan::get_byte<0>(u16type));
                        buf.push_back(Botan::get_byte<1>(u16type));
                     }
                     result.test_eq("Hello extensions", Botan::hex_encode(buf), extensions);
                  },
                  Botan::TLS::Server_Hello_13::parse(buffer));
            } catch(const std::exception& ex) {
               result.test_eq("correct error produced", ex.what(), exception);
               result.confirm("negative test", !is_positive_test);
            }
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("tls", "tls_13_messages", TLS_13_Message_Parsing_Test);

   #endif

#endif

}  // namespace

}  // namespace Botan_Tests
