/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_TLS)

#include <botan/tls_policy.h>
#include <botan/tls_version.h>

namespace Botan_CLI {

class TLS_All_Policy : public Botan::TLS::Policy
   {
   public:
      std::vector<std::string> allowed_ciphers() const override
         {
         return std::vector<std::string>{
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
         return { "SRP_SHA", "ECDHE_PSK", "DHE_PSK", "PSK",
                  "CECPQ1", "ECDH", "DH", "RSA" };
         }

      std::vector<std::string> allowed_signature_methods() const override
         {
         return { "ECDSA", "RSA", "DSA" };
         };
   };

class TLS_Ciphersuites final : public Command
   {
   public:
      TLS_Ciphersuites() : Command("tls_ciphers --policy=default --version=tls1.2") {}

      static Botan::TLS::Protocol_Version::Version_Code tls_version_from_str(const std::string& str)
         {
         if(str == "tls1.2" || str == "TLS1.2" || str == "TLS-1.2")
            return Botan::TLS::Protocol_Version::TLS_V12;
         else if(str == "tls1.1" || str == "TLS1.1" || str == "TLS-1.1")
            return Botan::TLS::Protocol_Version::TLS_V11;
         else if(str == "tls1.0" || str == "TLS1.1" || str == "TLS-1.1")
            return Botan::TLS::Protocol_Version::TLS_V10;
         if(str == "dtls1.2" || str == "DTLS1.2" || str == "DTLS-1.2")
            return Botan::TLS::Protocol_Version::DTLS_V12;
         else if(str == "dtls1.0" || str == "DTLS1.0" || str == "DTLS-1.0")
            return Botan::TLS::Protocol_Version::DTLS_V10;
         else
            throw CLI_Error("Unknown TLS version '" + str + "'");
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
               throw CLI_Error("Error TLS policy '" + policy_type +
                               "' is neither a file nor a known policy type");
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

}

#endif
