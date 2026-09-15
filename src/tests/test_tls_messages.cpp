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
   #include <botan/mac.h>
   #include <botan/ocsp.h>
   #include <botan/tls_alert.h>
   #include <botan/tls_callbacks.h>
   #include <botan/tls_ciphersuite.h>
   #include <botan/tls_policy.h>
   #include <botan/tls_version.h>
   #include <botan/internal/loadstor.h>
   #include <botan/internal/tls_reader.h>
   #include <algorithm>
   #include <exception>

   #if defined(BOTAN_HAS_TLS_12)
      #include <botan/tls_extensions.h>
      #include <botan/tls_messages_12.h>
   #endif

   #if defined(BOTAN_HAS_TLS_13)
      #include "test_rng.h"
      #include <botan/tls_extensions_13.h>
      #include <botan/tls_messages_13.h>
   #endif
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_TLS)

   #if defined(BOTAN_HAS_TLS_12)
Test::Result test_hello_verify_request() {
   Test::Result result("hello_verify_request construction");

   const std::vector<uint8_t> test_data;
   std::vector<uint8_t> key_data(32);
   const Botan::SymmetricKey sk(key_data);

   // Compute cookie over an empty string with an empty test data
   const Botan::TLS::Hello_Verify_Request hfr(test_data, "", sk);

   // Compute HMAC
   auto hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
   hmac->set_key(sk);
   hmac->update_be(uint64_t(0));  // length of client hello
   hmac->update_be(uint64_t(0));  // length of client identity
   std::vector<uint8_t> test = hmac->final<std::vector<uint8_t>>();

   result.test_bin_eq("Cookie comparison", hfr.cookie(), test);
   return result;
}

Test::Result test_srtp_extension_ignores_mki() {
   Test::Result result("SRTP use_srtp extension ignores non-empty MKI");

   // RFC 5764 use_srtp: one profile (srtp_aes128_cm_hmac_sha1_80 = 0x0001)
   // followed by a non-empty srtp_mki ("bogus"). Parsing must accept and ignore
   // the MKI rather than reject the extension.
   const std::vector<uint8_t> ext = {0x00, 0x02, 0x00, 0x01, 0x05, 0x62, 0x6f, 0x67, 0x75, 0x73};

   Botan::TLS::TLS_Data_Reader reader("test_srtp", ext);
   const Botan::TLS::SRTP_Protection_Profiles srtp(reader, static_cast<uint16_t>(ext.size()));

   result.test_sz_eq("one profile parsed", srtp.profiles().size(), 1);

   // serialize() answers with an empty srtp_mki (trailing 0x00) regardless of the
   // received MKI, per RFC 5764 4.1.3 option 2.
   const std::vector<uint8_t> expected = {0x00, 0x02, 0x00, 0x01, 0x00};
   result.test_bin_eq(
      "re-serialized use_srtp carries an empty MKI", srtp.serialize(Botan::TLS::Connection_Side::Server), expected);

   return result;
}
   #endif

class Test_Callbacks : public Botan::TLS::Callbacks {
   public:
      explicit Test_Callbacks(Test::Result& result) : m_result(result) {}

   public:
      void tls_emit_data(std::span<const uint8_t> /*data*/) override {
         m_result.test_failure("unsolicited call to tls_emit_data");
      }

      void tls_record_received(uint64_t /*rec_no*/, std::span<const uint8_t> /*data*/) override {
         m_result.test_failure("unsolicited call to tls_record_received");
      }

      void tls_alert(Botan::TLS::Alert /*alert*/) override { m_result.test_failure("unsolicited call to tls_alert"); }

      void tls_session_established(const Botan::TLS::Session_Summary& /*session_info*/) override {
         m_result.test_failure("unsolicited call to tls_session_established");
      }

   private:
      Test::Result& m_result;
};

   #if defined(BOTAN_HAS_TLS_12)
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
                  const Botan::TLS::Certificate_Verify message(buffer);
               } else if(algo == "client_hello") {
                  const std::string extensions = vars.get_req_str("AdditionalData");
                  const Botan::TLS::Protocol_Version pv(protocol[0], protocol[1]);
                  const Botan::TLS::Client_Hello_12 message(buffer);
                  result.test_str_eq("Protocol version", message.legacy_version().to_string(), pv.to_string());
                  std::vector<uint8_t> buf;
                  for(const Botan::TLS::Extension_Code& type : message.extension_types()) {
                     const uint16_t u16type = static_cast<uint16_t>(type);
                     buf.push_back(Botan::get_byte<0>(u16type));
                     buf.push_back(Botan::get_byte<1>(u16type));
                  }
                  result.test_bin_eq("Hello extensions", buf, extensions);
               } else if(algo == "hello_verify") {
                  const Botan::TLS::Hello_Verify_Request message(buffer);
               } else if(algo == "hello_request") {
                  const Botan::TLS::Hello_Request message(buffer);
               } else if(algo == "new_session_ticket") {
                  const Botan::TLS::New_Session_Ticket_12 message(buffer);
               } else if(algo == "server_hello") {
                  const std::string extensions = vars.get_req_str("AdditionalData");
                  const Botan::TLS::Protocol_Version pv(protocol[0], protocol[1]);
                  const Botan::TLS::Ciphersuite cs =
                     Botan::TLS::Ciphersuite::by_id(Botan::make_uint16(ciphersuite[0], ciphersuite[1])).value();
                  const Botan::TLS::Server_Hello_12 message(buffer);
                  result.test_str_eq("Protocol version", message.legacy_version().to_string(), pv.to_string());
                  result.test_is_true("Ciphersuite", (message.ciphersuite() == cs.ciphersuite_code()));
                  std::vector<uint8_t> buf;
                  for(const Botan::TLS::Extension_Code& type : message.extension_types()) {
                     const uint16_t u16type = static_cast<uint16_t>(type);
                     buf.push_back(Botan::get_byte<0>(u16type));
                     buf.push_back(Botan::get_byte<1>(u16type));
                  }
                  result.test_bin_eq("Hello extensions", buf, extensions);
               } else if(algo == "alert") {
                  const Botan::secure_vector<uint8_t> sb(buffer.begin(), buffer.end());
                  const Botan::TLS::Alert message(sb);
                  result.test_sz_lt(
                     "Alert type vectors result to UNKNOWN_CA or ACCESS_DENIED, which is shorter than 15",
                     message.type_string().size(),
                     15);
               } else if(algo == "cert_status") {
                  const Botan::TLS::Certificate_Status message(buffer, Botan::TLS::Connection_Side::Server);

                  const Botan::OCSP::Response resp(message.response());

                  const std::vector<std::string> CNs = resp.signer_name().get_attribute("CN");

                  // This is not required by OCSP protocol, we are just using it as a test here
                  if(result.test_sz_eq("OCSP response has signer name", CNs.size(), 1)) {
                     result.test_str_eq("Expected name", CNs[0], expected_name);
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
                  const Botan::TLS::Certificate_Verify message(buffer);
               });
            } else if(algo == "client_hello") {
               result.test_throws("invalid client_hello input", exception, [&buffer]() {
                  const Botan::TLS::Client_Hello_12 message(buffer);
               });
            } else if(algo == "hello_verify") {
               result.test_throws("invalid hello_verify input", exception, [&buffer]() {
                  const Botan::TLS::Hello_Verify_Request message(buffer);
               });
            } else if(algo == "hello_request") {
               result.test_throws("invalid hello_request input", exception, [&buffer]() {
                  const Botan::TLS::Hello_Request message(buffer);
               });
            } else if(algo == "cert_status") {
               result.test_throws("invalid cert_status input", exception, [&buffer]() {
                  const Botan::TLS::Certificate_Status message(buffer, Botan::TLS::Connection_Side::Server);
               });
            } else if(algo == "new_session_ticket") {
               result.test_throws("invalid new_session_ticket input", exception, [&buffer]() {
                  const Botan::TLS::New_Session_Ticket_12 message(buffer);
               });
            } else if(algo == "server_hello") {
               result.test_throws("invalid server_hello input", exception, [&buffer]() {
                  const Botan::TLS::Server_Hello_12 message(buffer);
               });
            } else if(algo == "alert") {
               result.test_throws("invalid alert input", exception, [&buffer]() {
                  const Botan::secure_vector<uint8_t> sb(buffer.begin(), buffer.end());
                  const Botan::TLS::Alert message(sb);
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
         results.push_back(test_srtp_extension_ignores_mki());

         return results;
      }
};

BOTAN_REGISTER_TEST("tls", "tls_messages", TLS_Message_Parsing_Test);
   #endif

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
         const Botan::TLS::Text_Policy policy("key_exchange_groups = " + groups +
                                              "\n"
                                              "key_exchange_groups_to_offer = " +
                                              offered_groups);
         Fixed_Output_RNG rng;
         rng.add_entropy(rng_data.data(), rng_data.size());

         const Botan::TLS::Key_Share share(policy, cb, rng);
         const auto serialized_buffer = share.serialize(Botan::TLS::Connection_Side::Client);

         result.test_bin_eq("key_share_CH_offers test", serialized_buffer, expected_key_share);

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
         const std::string exception = vars.get_req_str("Exception");
         const bool is_positive_test = exception.empty();

         Test::Result result(extension + " parsing");

         if(is_positive_test) {
            try {
               if(extension == "supported_version") {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("ClientHello", buffer);
                  const Botan::TLS::Supported_Versions supported_versions(
                     tls_data_reader, static_cast<uint16_t>(buffer.size()), Botan::TLS::Connection_Side::Client);
                  const auto serialized_buffer = supported_versions.serialize(Botan::TLS::Connection_Side::Client);

                  const std::vector<std::vector<uint8_t>> expected_versions = vars.get_req_bin_list("Expected_Content");
                  for(const auto& expected_version : expected_versions) {
                     result.test_is_true("Expected_Content",
                                         supported_versions.supports(
                                            Botan::TLS::Protocol_Version(expected_version[0], expected_version[1])));
                  }

                  result.test_bin_eq("supported_version test 1", serialized_buffer, buffer);
               } else if(extension == "supported_groups") {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("ClientHello", buffer);
                  const Botan::TLS::Supported_Groups supp_groups_ext(tls_data_reader,
                                                                     static_cast<uint16_t>(buffer.size()));

                  const auto serialized_buffer = supp_groups_ext.serialize(Botan::TLS::Connection_Side::Client);
                  const auto expected_content = vars.get_req_bin("Expected_Content");

                  const auto dh_groups = supp_groups_ext.dh_groups();
                  const auto ec_groups = supp_groups_ext.ec_groups();

                  std::vector<Botan::TLS::Named_Group> named_groups;
                  std::merge(dh_groups.begin(),
                             dh_groups.end(),
                             ec_groups.begin(),
                             ec_groups.end(),
                             std::back_inserter(named_groups));

                  result.test_is_true("supported_groups extension - size check",
                                      (named_groups.size() * 2) == expected_content.size());

                  for(size_t i = 0; i < expected_content.size(); i += 2) {
                     const auto expected_named_group =
                        Botan::make_uint16(expected_content.at(i), expected_content.at(i + 1));

                     result.test_is_true(
                        "signature_algorithms_cert extension - named group check",
                        std::any_of(named_groups.cbegin(),
                                    named_groups.cend(),
                                    [&expected_named_group](const Botan::TLS::Named_Group& named_group) {
                                       return static_cast<Botan::TLS::Named_Group>(expected_named_group) == named_group;
                                    }));
                  }

                  result.test_bin_eq("supported_groups extension - serialization test", serialized_buffer, buffer);
               } else if(extension == "signature_algorithms_cert") {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("ClientHello", buffer);
                  const Botan::TLS::Signature_Algorithms_Cert sig_algo_cert(tls_data_reader,
                                                                            static_cast<uint16_t>(buffer.size()));

                  const auto serialized_buffer = sig_algo_cert.serialize(Botan::TLS::Connection_Side::Client);
                  const auto expected_content = vars.get_req_bin("Expected_Content");

                  result.test_is_true("signature_algorithms_cert extension - size check",
                                      sig_algo_cert.supported_schemes().size() * 2 == expected_content.size());

                  size_t offset = 0;
                  for(const auto& sig_scheme : sig_algo_cert.supported_schemes()) {
                     const auto expected_sig_scheme =
                        Botan::make_uint16(expected_content.at(offset), expected_content.at(offset + 1));

                     result.test_is_true("signature_algorithms_cert extension - sig scheme check",
                                         Botan::TLS::Signature_Scheme(expected_sig_scheme) == sig_scheme);

                     offset += 2;
                  }

                  result.test_bin_eq(
                     "signature_algorithms_cert extension - serialization test", serialized_buffer, buffer);
               } else if(extension == "cookie") {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("HelloRetryRequest", buffer);
                  const Botan::TLS::Cookie cookie(tls_data_reader, static_cast<uint16_t>(buffer.size()));

                  const auto serialized_buffer = cookie.serialize(Botan::TLS::Connection_Side::Server);
                  const auto expected_cookie = vars.get_req_bin("Expected_Content");

                  result.test_bin_eq("Cookie extension test", expected_cookie, cookie.get_cookie());
               } else if(extension == "key_share_HRR") {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("HelloRetryRequest", buffer);
                  const Botan::TLS::Key_Share key_share(tls_data_reader,
                                                        static_cast<uint16_t>(buffer.size()),
                                                        Botan::TLS::Handshake_Type::HelloRetryRequest);

                  const auto serialized_buffer = key_share.serialize(Botan::TLS::Connection_Side::Client);
                  const auto expected_key_share = vars.get_req_bin("Expected_Content");

                  result.test_bin_eq("key_share_HRR test", serialized_buffer, expected_key_share);
               } else if(extension == "key_share_SH") {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("ServerHello", buffer);
                  const Botan::TLS::Key_Share key_share(
                     tls_data_reader, static_cast<uint16_t>(buffer.size()), Botan::TLS::Handshake_Type::ServerHello);

                  const auto serialized_buffer = key_share.serialize(Botan::TLS::Connection_Side::Client);
                  const auto expected_key_share = vars.get_req_bin("Expected_Content");

                  result.test_bin_eq("key_share_SH test", serialized_buffer, expected_key_share);
               } else if(extension == "key_share_CH") {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("ClientHello", buffer);
                  const Botan::TLS::Key_Share key_share(
                     tls_data_reader, static_cast<uint16_t>(buffer.size()), Botan::TLS::Handshake_Type::ClientHello);

                  const auto serialized_buffer = key_share.serialize(Botan::TLS::Connection_Side::Server);
                  const auto expected_key_share = vars.get_req_bin("Expected_Content");

                  result.test_bin_eq("key_share_CH test", serialized_buffer, expected_key_share);
               } else if(extension == "alpn") {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("ClientHello", buffer);
                  const Botan::TLS::Application_Layer_Protocol_Notification alpn(
                     tls_data_reader, static_cast<uint16_t>(buffer.size()), Botan::TLS::Connection_Side::Client);

                  std::string protocols_joined;
                  for(const auto& p : alpn.protocols()) {
                     if(!protocols_joined.empty()) {
                        protocols_joined.push_back(',');
                     }
                     protocols_joined += p;
                  }
                  result.test_str_eq("alpn protocols", protocols_joined, vars.get_req_str("Expected_Content"));
               } else if(extension == "server_name") {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("ClientHello", buffer);
                  const Botan::TLS::Server_Name_Indicator sni(
                     tls_data_reader, static_cast<uint16_t>(buffer.size()), Botan::TLS::Connection_Side::Client);

                  result.test_str_eq("server_name host_name", sni.host_name(), vars.get_req_str("Expected_Content"));
               } else {
                  throw Test_Error("Unknown extension type " + extension + " in TLS parsing tests");
               }
               result.test_success("Correct parsing");
            } catch(std::exception& e) {
               result.test_failure(e.what());
            }
         } else {
            if(extension == "cookie") {
               result.test_throws("invalid cookie extension input", exception, [&buffer]() {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("HelloRetryRequest", buffer);
                  const Botan::TLS::Cookie cookie(tls_data_reader, static_cast<uint16_t>(buffer.size()));
               });
            } else if(extension == "supported_groups") {
               result.test_throws("invalid supported_groups extension input", exception, [&buffer]() {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("ClientHello", buffer);
                  const Botan::TLS::Supported_Groups supp_groups_ext(tls_data_reader,
                                                                     static_cast<uint16_t>(buffer.size()));
               });
            } else if(extension == "key_share_CH") {
               result.test_throws("invalid key_share_CH extension input", exception, [&buffer]() {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("ClientHello", buffer);
                  const Botan::TLS::Key_Share key_share(
                     tls_data_reader, static_cast<uint16_t>(buffer.size()), Botan::TLS::Handshake_Type::ClientHello);
               });
            } else if(extension == "key_share_HRR") {
               result.test_throws("invalid key_share_HRR extension input", exception, [&buffer]() {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("HelloRetryRequest", buffer);
                  const Botan::TLS::Key_Share key_share(tls_data_reader,
                                                        static_cast<uint16_t>(buffer.size()),
                                                        Botan::TLS::Handshake_Type::HelloRetryRequest);
               });
            } else if(extension == "key_share_SH") {
               result.test_throws("invalid key_share_SH extension input", exception, [&buffer]() {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("ServerHello", buffer);
                  const Botan::TLS::Key_Share key_share(
                     tls_data_reader, static_cast<uint16_t>(buffer.size()), Botan::TLS::Handshake_Type::ServerHello);
               });
            } else if(extension == "signature_algorithms_cert") {
               result.test_throws("invalid signature_algorithms_cert extension input", exception, [&buffer]() {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("Extension", buffer);
                  const Botan::TLS::Signature_Algorithms_Cert sig_algo_cert(tls_data_reader,
                                                                            static_cast<uint16_t>(buffer.size()));
               });
            } else if(extension == "alpn") {
               result.test_throws("invalid alpn extension input", exception, [&buffer]() {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("ClientHello", buffer);
                  const Botan::TLS::Application_Layer_Protocol_Notification alpn(
                     tls_data_reader, static_cast<uint16_t>(buffer.size()), Botan::TLS::Connection_Side::Client);
               });
            } else if(extension == "server_name") {
               result.test_throws("invalid server_name extension input", exception, [&buffer]() {
                  Botan::TLS::TLS_Data_Reader tls_data_reader("ClientHello", buffer);
                  const Botan::TLS::Server_Name_Indicator sni(
                     tls_data_reader, static_cast<uint16_t>(buffer.size()), Botan::TLS::Connection_Side::Client);
               });
            } else {
               throw Test_Error("Unknown extension type " + extension + " in TLS parsing negative tests");
            }
         }

         return result;
      }

      std::vector<Test::Result> run_final_tests() override {
         std::vector<Test::Result> results;

      #if defined(BOTAN_HAS_TLS_12)
         results.push_back(test_hello_verify_request());
      #endif

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
                     if constexpr(std::is_same_v<Botan::TLS::Client_Hello_12_Shim, decltype(ch)>) {
                        result.test_is_true("expected Client_Hello_12_Shim", msg_type == "client_hello_12");
                     }
                     if constexpr(std::is_same_v<Botan::TLS::Client_Hello_13, decltype(ch)>) {
                        result.test_is_true("expected Client_Hello_13", msg_type == "client_hello_13");
                     }

                     const std::string extensions = vars.get_req_str("AdditionalData");
                     std::vector<uint8_t> exts_buffer;
                     for(const Botan::TLS::Extension_Code& type : ch.extensions().extension_types()) {
                        const uint16_t u16type = static_cast<uint16_t>(type);
                        exts_buffer.push_back(Botan::get_byte<0>(u16type));
                        exts_buffer.push_back(Botan::get_byte<1>(u16type));
                     }
                     result.test_bin_eq("Hello extensions", exts_buffer, extensions);

                     std::vector<uint8_t> ciphersuites_buffer;
                     for(const auto& cs : ch.ciphersuites()) {
                        ciphersuites_buffer.push_back(Botan::get_byte<0>(cs));
                        ciphersuites_buffer.push_back(Botan::get_byte<1>(cs));
                     }
                     result.test_bin_eq("Supported ciphersuites", ciphersuites_buffer, ciphersuite);

                     result.test_is_true("this is a positive test that should not have failed yet", is_positive_test);
                  },
                  Botan::TLS::Client_Hello_13::parse(buffer));
            } catch(const std::exception& ex) {
               result.test_str_eq("correct error produced", ex.what(), exception);
               result.test_is_true("negative test", !is_positive_test);
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
                     if constexpr(std::is_same_v<Botan::TLS::Server_Hello_12_Shim, decltype(msg)>) {
                        result.test_is_true("expected Server_Hello_12", msg_type == "server_hello_12");
                        result.test_is_true("expected pre TLS 1.3 message", pv == msg.selected_version());
                     } else if constexpr(std::is_same_v<Botan::TLS::Server_Hello_13, decltype(msg)>) {
                        result.test_is_true("expected Server_Hello_13", msg_type == "server_hello_13");
                     } else if constexpr(std::is_same_v<Botan::TLS::Hello_Retry_Request, decltype(msg)>) {
                        result.test_is_true("expected Hello_Retry_Request", msg_type == "hello_retry_request");
                     }

                     result.test_is_true("Ciphersuite", (msg.ciphersuite() == cs.ciphersuite_code()));

                     std::vector<uint8_t> buf;
                     for(const Botan::TLS::Extension_Code& type : msg.extensions().extension_types()) {
                        const uint16_t u16type = static_cast<uint16_t>(type);
                        buf.push_back(Botan::get_byte<0>(u16type));
                        buf.push_back(Botan::get_byte<1>(u16type));
                     }
                     result.test_bin_eq("Hello extensions", buf, extensions);
                  },
                  Botan::TLS::Server_Hello_13::parse(buffer));
            } catch(const std::exception& ex) {
               result.test_str_eq("correct error produced", ex.what(), exception);
               result.test_is_true("negative test", !is_positive_test);
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
