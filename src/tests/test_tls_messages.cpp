/*
* (C) 2016 Juraj Somorovsky
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS)
   #include <exception>
   #include <botan/hex.h>
   #include <botan/mac.h>
   #include <botan/tls_ciphersuite.h>
   #include <botan/tls_handshake_msg.h>
   #include <botan/tls_messages.h>
   #include <botan/tls_alert.h>
   #include <botan/loadstor.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_TLS)
Test::Result test_hello_verify_request()
   {
   Test::Result result("hello_verify_request construction");

   std::vector<uint8_t> test_data;
   std::vector<uint8_t> key_data(32);
   Botan::SymmetricKey sk(key_data);

   // Compute cookie over an empty string with an empty test data
   Botan::TLS::Hello_Verify_Request hfr(test_data, "", sk);

   // Compute HMAC
   std::unique_ptr<Botan::MessageAuthenticationCode> hmac(Botan::MessageAuthenticationCode::create("HMAC(SHA-256)"));
   hmac->set_key(sk);
   hmac->update_be(uint64_t(0)); // length of client hello
   hmac->update_be(uint64_t(0)); // length of client identity
   std::vector<uint8_t> test = unlock(hmac->final());

   result.test_eq("Cookie comparison", hfr.cookie(), test);
   return result;
   }

class TLS_Message_Parsing_Test final : public Text_Based_Test
   {
   public:
      TLS_Message_Parsing_Test()
         : Text_Based_Test("tls", "Buffer,Protocol,Ciphersuite,AdditionalData,Name,Exception") {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<uint8_t> buffer      = vars.get_req_bin("Buffer");
         const std::vector<uint8_t> protocol    = vars.get_opt_bin("Protocol");
         const std::vector<uint8_t> ciphersuite = vars.get_opt_bin("Ciphersuite");
         const std::string exception            = vars.get_req_str("Exception");
         const std::string expected_name        = vars.get_opt_str("Name", "");
         const bool is_positive_test            = exception.empty();

         Test::Result result(algo + " parsing");

         if(is_positive_test)
            {
            try
               {
               if(algo == "cert_verify")
                  {
                  Botan::TLS::Protocol_Version pv(protocol[0], protocol[1]);
                  Botan::TLS::Certificate_Verify message(buffer, pv);
                  }
               else if(algo == "client_hello")
                  {
                  const std::string extensions = vars.get_req_str("AdditionalData");
                  Botan::TLS::Protocol_Version pv(protocol[0], protocol[1]);
                  Botan::TLS::Client_Hello message(buffer);
                  result.test_eq("Protocol version", message.version().to_string(), pv.to_string());
                  std::vector<uint8_t> buf;
                  for(Botan::TLS::Handshake_Extension_Type const& type : message.extension_types())
                     {
                     uint16_t u16type = static_cast<uint16_t>(type);
                     buf.push_back(Botan::get_byte(0, u16type));
                     buf.push_back(Botan::get_byte(1, u16type));
                     }
                  result.test_eq("Hello extensions", Botan::hex_encode(buf), extensions);
                  }
               else if(algo == "hello_verify")
                  {
                  Botan::TLS::Hello_Verify_Request message(buffer);
                  }
               else if(algo == "hello_request")
                  {
                  Botan::TLS::Hello_Request message(buffer);
                  }
               else if(algo == "new_session_ticket")
                  {
                  Botan::TLS::New_Session_Ticket message(buffer);
                  }
               else if(algo == "server_hello")
                  {
                  const std::string extensions = vars.get_req_str("AdditionalData");
                  Botan::TLS::Protocol_Version pv(protocol[0], protocol[1]);
                  Botan::TLS::Ciphersuite cs = Botan::TLS::Ciphersuite::by_id(Botan::make_uint16(ciphersuite[0], ciphersuite[1]));
                  Botan::TLS::Server_Hello message(buffer);
                  result.test_eq("Protocol version", message.version().to_string(), pv.to_string());
                  result.confirm("Ciphersuite", (message.ciphersuite() == cs.ciphersuite_code()));
                  std::vector<uint8_t> buf;
                  for(Botan::TLS::Handshake_Extension_Type const& type : message.extension_types())
                     {
                     uint16_t u16type = static_cast<uint16_t>(type);
                     buf.push_back(Botan::get_byte(0, u16type));
                     buf.push_back(Botan::get_byte(1, u16type));
                     }
                  result.test_eq("Hello extensions", Botan::hex_encode(buf), extensions);
                  }
               else if(algo == "alert")
                  {
                  Botan::secure_vector<uint8_t> sb(buffer.begin(), buffer.end());
                  Botan::TLS::Alert message(sb);
                  result.test_lt("Alert type vectors result to UNKNOWN_CA or ACCESS_DENIED, which is shorter than 15",
                                 message.type_string().size(), 15);
                  }
               else if(algo == "cert_status")
                  {
                  Botan::TLS::Certificate_Status message(buffer);

                  Botan::OCSP::Response resp(message.response());

                  const std::vector<std::string> CNs = resp.signer_name().get_attribute("CN");

                  // This is not requird by OCSP protocol, we are just using it as a test here
                  if(result.test_eq("OCSP response has signer name", CNs.size(), 1))
                     {
                     result.test_eq("Expected name", CNs[0], expected_name);
                     }
                  }
               else
                  {
                  throw Test_Error("Unknown message type " + algo + " in TLS parsing tests");
                  }
               result.test_success("Correct parsing");
               }
            catch(std::exception& e)
               {
               result.test_failure(e.what());
               }
            }
         else
            {
            if(algo == "cert_verify")
               {
               Botan::TLS::Protocol_Version pv(protocol[0], protocol[1]);
               result.test_throws("invalid cert_verify input", exception, [&buffer, &pv]()
                  {
                  Botan::TLS::Certificate_Verify message(buffer, pv);
                  });
               }
            else if(algo == "client_hello")
               {
               result.test_throws("invalid client_hello input", exception, [&buffer]()
                  {
                  Botan::TLS::Client_Hello message(buffer);
                  });
               }
            else if(algo == "hello_verify")
               {
               result.test_throws("invalid hello_verify input", exception, [&buffer]()
                  {
                  Botan::TLS::Hello_Verify_Request message(buffer);
                  });
               }
            else if(algo == "hello_request")
               {
               result.test_throws("invalid hello_request input", exception, [&buffer]()
                  {
                  Botan::TLS::Hello_Request message(buffer);
                  });
               }
            else if(algo == "cert_status")
               {
               result.test_throws("invalid cert_status input", exception, [&buffer]()
                  {
                  Botan::TLS::Certificate_Status message(buffer);
                  });
               }
            else if(algo == "new_session_ticket")
               {
               result.test_throws("invalid new_session_ticket input", exception, [&buffer]()
                  {
                  Botan::TLS::New_Session_Ticket message(buffer);
                  });
               }
            else if(algo == "server_hello")
               {
               result.test_throws("invalid server_hello input", exception, [&buffer]()
                  {
                  Botan::TLS::Server_Hello message(buffer);
                  });
               }
            else if(algo == "alert")
               {
               result.test_throws("invalid alert input", exception, [&buffer]()
                  {
                  Botan::secure_vector<uint8_t> sb(buffer.begin(), buffer.end());
                  Botan::TLS::Alert message(sb);
                  });
               }
            else
               {
               throw Test_Error("Unknown message type " + algo + " in TLS parsing tests");
               }
            }

         return result;
         }

      std::vector<Test::Result> run_final_tests() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_hello_verify_request());

         return results;
         }
   };

BOTAN_REGISTER_TEST("tls", "tls_messages", TLS_Message_Parsing_Test);

#endif

}

}
