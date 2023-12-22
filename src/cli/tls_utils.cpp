/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

   #include <botan/hex.h>
   #include <botan/tls_messages.h>
   #include <botan/tls_policy.h>
   #include <botan/tls_version.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/loadstor.h>
   #include <botan/internal/stl_util.h>
   #include <sstream>

   #include "tls_helpers.h"

namespace Botan_CLI {

class TLS_Ciphersuites final : public Command {
   public:
      TLS_Ciphersuites() : Command("tls_ciphers --policy=default --version=tls1.2") {}

      static Botan::TLS::Protocol_Version tls_version_from_str(const std::string& str) {
         if(str == "tls1.2" || str == "TLS1.2" || str == "TLS-1.2") {
            return Botan::TLS::Protocol_Version::TLS_V12;
         }
         if(str == "dtls1.2" || str == "DTLS1.2" || str == "DTLS-1.2") {
            return Botan::TLS::Protocol_Version::DTLS_V12;
         } else {
            throw CLI_Error("Unknown TLS version '" + str + "'");
         }
      }

      std::string group() const override { return "tls"; }

      std::string description() const override { return "Lists all ciphersuites for a policy and TLS version"; }

      void go() override {
         const std::string policy_type = get_arg("policy");
         const Botan::TLS::Protocol_Version version = tls_version_from_str(get_arg("version"));

         auto policy = load_tls_policy(policy_type);

         if(policy->acceptable_protocol_version(version) == false) {
            error_output() << "Error: the policy specified does not allow the given TLS version\n";
            return;
         }

         for(uint16_t suite_id : policy->ciphersuite_list(version)) {
            const auto s = Botan::TLS::Ciphersuite::by_id(suite_id);
            output() << ((s) ? s->to_string() : "unknown cipher suite") << "\n";
         }
      }
};

BOTAN_REGISTER_COMMAND("tls_ciphers", TLS_Ciphersuites);

   #if defined(BOTAN_HAS_TLS_13)

class TLS_Client_Hello_Reader final : public Command {
   public:
      TLS_Client_Hello_Reader() : Command("tls_client_hello --hex input") {}

      std::string group() const override { return "tls"; }

      std::string description() const override { return "Parse a TLS client hello message"; }

      void go() override {
         const std::string input_file = get_arg("input");
         std::vector<uint8_t> input;

         if(flag_set("hex")) {
            input = Botan::hex_decode(slurp_file_as_str(input_file));
         } else {
            input = slurp_file(input_file);
         }

         if(input.size() < 45) {
            error_output() << "Input too short to be valid\n";
            return;
         }

         // Input also contains the record layer header, strip it
         if(input[0] == 22) {
            const size_t len = Botan::make_uint16(input[3], input[4]);

            if(input.size() != len + 5) {
               error_output() << "Record layer length invalid\n";
               return;
            }

            input = std::vector<uint8_t>(input.begin() + 5, input.end());
         }

         // Assume the handshake header is there, strip it
         if(input[0] == 1) {
            const size_t hs_len = Botan::make_uint32(0, input[1], input[2], input[3]);

            if(input.size() != hs_len + 4) {
               error_output() << "Handshake layer length invalid\n";
               return;
            }

            input = std::vector<uint8_t>(input.begin() + 4, input.end());
         }

         try {
            auto hello = Botan::TLS::Client_Hello_13::parse(input);

            output() << format_hello(hello);
         } catch(std::exception& e) {
            error_output() << "Parsing client hello failed: " << e.what() << "\n";
         }
      }

   private:
      static std::string format_hello(
         const std::variant<Botan::TLS::Client_Hello_13, Botan::TLS::Client_Hello_12>& hello) {
         std::ostringstream oss;

         const auto* hello_base =
            std::visit([](const auto& ch) -> const Botan::TLS::Client_Hello* { return &ch; }, hello);

         const auto version = std::visit(Botan::overloaded{
                                            [](const Botan::TLS::Client_Hello_12&) { return "1.2"; },
                                            [](const Botan::TLS::Client_Hello_13&) { return "1.3"; },
                                         },
                                         hello);

         oss << "Version: " << version << "\n"
             << "Random: " << Botan::hex_encode(hello_base->random()) << "\n";

         if(!hello_base->session_id().empty()) {
            oss << "SessionID: " << Botan::hex_encode(hello_base->session_id().get()) << "\n";
         }
         for(uint16_t csuite_id : hello_base->ciphersuites()) {
            const auto csuite = Botan::TLS::Ciphersuite::by_id(csuite_id);
            if(csuite && csuite->valid()) {
               oss << "Cipher: " << csuite->to_string() << "\n";
            } else if(csuite_id == 0x00FF) {
               oss << "Cipher: EMPTY_RENEGOTIATION_INFO_SCSV\n";
            } else {
               oss << "Cipher: Unknown (" << std::hex << csuite_id << ")\n";
            }
         }

         oss << "Supported signature schemes: ";

         if(hello_base->signature_schemes().empty()) {
            oss << "Did not send signature_algorithms extension\n";
         } else {
            for(Botan::TLS::Signature_Scheme scheme : hello_base->signature_schemes()) {
               try {
                  auto s = scheme.to_string();
                  oss << s << " ";
               } catch(...) {
                  oss << "(" << std::hex << static_cast<unsigned int>(scheme.wire_code()) << ") ";
               }
            }
            oss << "\n";
         }

         if(auto sg = hello_base->extensions().get<Botan::TLS::Supported_Groups>()) {
            oss << "Supported Groups: ";
            for(const auto group : sg->groups()) {
               oss << group.to_string().value_or(Botan::fmt("Unknown group: {}", group.wire_code())) << " ";
            }
            oss << "\n";
         }

         std::map<std::string, bool> hello_flags;
         hello_flags["ALPN"] = hello_base->supports_alpn();

         std::visit(Botan::overloaded{
                       [&](const Botan::TLS::Client_Hello_12& ch12) {
                          hello_flags["Encrypt Then Mac"] = ch12.supports_encrypt_then_mac();
                          hello_flags["Extended Master Secret"] = ch12.supports_extended_master_secret();
                          hello_flags["Session Ticket"] = ch12.supports_session_ticket();
                       },
                       [&](const Botan::TLS::Client_Hello_13& ch13) {
                          if(auto ks = ch13.extensions().get<Botan::TLS::Key_Share>()) {
                             oss << "Key Shares: ";
                             for(const auto group : ks->offered_groups()) {
                                oss << group.to_string().value_or(Botan::fmt("Unknown group: {}", group.wire_code()))
                                    << " ";
                             }
                             oss << "\n";
                          }
                       },
                    },
                    hello);

         for(auto&& i : hello_flags) {
            oss << "Supports " << i.first << "? " << (i.second ? "yes" : "no") << "\n";
         }

         return oss.str();
      }
};

BOTAN_REGISTER_COMMAND("tls_client_hello", TLS_Client_Hello_Reader);

   #endif

}  // namespace Botan_CLI

#endif
