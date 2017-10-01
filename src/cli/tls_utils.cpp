/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_TLS)

#include <botan/tls_policy.h>
#include <botan/tls_version.h>
#include <botan/tls_messages.h>
#include <botan/hex.h>
#include <sstream>

namespace Botan_CLI {

class TLS_All_Policy : public Botan::TLS::Policy
   {
   public:
      std::vector<std::string> allowed_ciphers() const override
         {
         return std::vector<std::string>
            {
            "ChaCha20Poly1305",
            "AES-256/OCB(12)",
            "AES-128/OCB(12)",
            "AES-256/GCM",
            "AES-128/GCM",
            "AES-256/CCM",
            "AES-128/CCM",
            "AES-256/CCM(8)",
            "AES-128/CCM(8)",
            "Camellia-256/GCM",
            "Camellia-128/GCM",
            "AES-256",
            "AES-128",
            "Camellia-256",
            "Camellia-128",
            "SEED"
            "3DES"
            };
         }

      std::vector<std::string> allowed_key_exchange_methods() const override
         {
         return { "SRP_SHA", "ECDHE_PSK", "DHE_PSK", "PSK", "CECPQ1", "ECDH", "DH", "RSA" };
         }

      std::vector<std::string> allowed_signature_methods() const override
         {
         return { "ECDSA", "RSA", "DSA" };
         }
   };

class TLS_Ciphersuites final : public Command
   {
   public:
      TLS_Ciphersuites()
         : Command("tls_ciphers --policy=default --version=tls1.2") {}

      static Botan::TLS::Protocol_Version::Version_Code tls_version_from_str(const std::string& str)
         {
         if(str == "tls1.2" || str == "TLS1.2" || str == "TLS-1.2")
            {
            return Botan::TLS::Protocol_Version::TLS_V12;
            }
         else if(str == "tls1.1" || str == "TLS1.1" || str == "TLS-1.1")
            {
            return Botan::TLS::Protocol_Version::TLS_V11;
            }
         else if(str == "tls1.0" || str == "TLS1.1" || str == "TLS-1.1")
            {
            return Botan::TLS::Protocol_Version::TLS_V10;
            }
         if(str == "dtls1.2" || str == "DTLS1.2" || str == "DTLS-1.2")
            {
            return Botan::TLS::Protocol_Version::DTLS_V12;
            }
         else if(str == "dtls1.0" || str == "DTLS1.0" || str == "DTLS-1.0")
            {
            return Botan::TLS::Protocol_Version::DTLS_V10;
            }
         else
            {
            throw CLI_Error("Unknown TLS version '" + str + "'");
            }
         }

      void go() override
         {
         const std::string policy_type = get_arg("policy");
         const Botan::TLS::Protocol_Version version(tls_version_from_str(get_arg("version")));
         const bool with_srp = false; // fixme

         std::unique_ptr<Botan::TLS::Policy> policy;

         if(policy_type == "default")
            {
            policy.reset(new Botan::TLS::Policy);
            }
         else if(policy_type == "suiteb")
            {
            policy.reset(new Botan::TLS::NSA_Suite_B_128);
            }
         else if(policy_type == "strict")
            {
            policy.reset(new Botan::TLS::Strict_Policy);
            }
         else if(policy_type == "all")
            {
            policy.reset(new TLS_All_Policy);
            }
         else
            {
            std::ifstream policy_file(policy_type);
            if(!policy_file.good())
               {
               throw CLI_Error("Error TLS policy '" + policy_type + "' is neither a file nor a known policy type");
               }

            policy.reset(new Botan::TLS::Text_Policy(policy_file));
            }

         for(uint16_t suite_id : policy->ciphersuite_list(version, with_srp))
            {
            const Botan::TLS::Ciphersuite suite(Botan::TLS::Ciphersuite::by_id(suite_id));
            output() << suite.to_string() << "\n";
            }
         }
   };

BOTAN_REGISTER_COMMAND("tls_ciphers", TLS_Ciphersuites);

class TLS_Client_Hello_Reader final : public Command
   {
   public:
      TLS_Client_Hello_Reader()
         : Command("tls_client_hello --hex input") {}

      void go() override
         {
         const std::string input_file = get_arg("input");
         std::vector<uint8_t> input;

         if(flag_set("hex"))
            {
            input = Botan::hex_decode(slurp_file_as_str(input_file));
            }
         else
            {
            input = slurp_file(input_file);
            }

         if(input.size() < 45)
            {
            error_output() << "Input too short to be valid\n";
            return;
            }

         // Input also contains the record layer header, strip it
         if(input[0] == 22)
            {
            const size_t len = Botan::make_uint16(input[3], input[4]);

            if(input.size() != len + 5)
               {
               error_output() << "Record layer length invalid\n";
               return;
               }

            input = std::vector<uint8_t>(input.begin() + 5, input.end());
            }

         // Assume the handshake header is there, strip it
         if(input[0] != 1)
            {
            error_output() << "Input message is not a TLS client hello\n";
            return;
            }

         const size_t hs_len = Botan::make_uint32(0, input[1], input[2], input[3]);

         if(input.size() != hs_len + 4)
            {
            error_output() << "Handshake layer length invalid\n";
            return;
            }

         input = std::vector<uint8_t>(input.begin() + 4, input.end());

         try
            {
            Botan::TLS::Client_Hello hello(input);

            output() << format_hello(hello);
            }
         catch(std::exception& e)
            {
            error_output() << "Parsing client hello failed: " << e.what() << "\n";
            }
         }

   private:
      std::string format_hello(const Botan::TLS::Client_Hello& hello)
         {
         std::ostringstream oss;
         oss << "Version: " << hello.version().to_string() << "\n"
             << "Random: " << Botan::hex_encode(hello.random()) << "\n";

         if(!hello.session_id().empty())
            oss << "SessionID: " << Botan::hex_encode(hello.session_id()) << "\n";
         for(uint16_t csuite_id : hello.ciphersuites())
            oss << "Cipher: " << Botan::TLS::Ciphersuite::by_id(csuite_id).to_string() << "\n";

         oss << "Supported signature schemes: ";

         if(hello.supported_algos().empty())
            {
            oss << "Did not send signature_algorithms extension\n";
            }
         else
            {
            for(auto&& hash_and_sig : hello.supported_algos())
               oss << hash_and_sig.second << '+' << hash_and_sig.first << ' ';
            oss << "\n";
            }

         std::map<std::string, bool> hello_flags;
         hello_flags["ALPN"] = hello.supports_alpn();
         hello_flags["Encrypt Then Mac"] = hello.supports_encrypt_then_mac();
         hello_flags["Extended Master Secret"] = hello.supports_extended_master_secret();
         hello_flags["Session Ticket"] = hello.supports_session_ticket();

         for(auto&& i : hello_flags)
            oss << "Supports " << i.first << "? " << (i.second ? "yes" : "no") << "\n";

         return oss.str();
         }
   };

BOTAN_REGISTER_COMMAND("tls_client_hello", TLS_Client_Hello_Reader);

}

#endif
