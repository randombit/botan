/*
* (C) 2014,2015,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CLI_TLS_HELPERS_H_
#define BOTAN_CLI_TLS_HELPERS_H_

#include <botan/pkcs8.h>
#include <botan/credentials_manager.h>
#include <botan/tls_policy.h>
#include <botan/x509self.h>
#include <botan/data_src.h>
#include <memory>
#include <fstream>

#include "cli_exceptions.h"

#if defined(BOTAN_HAS_CERTSTOR_SYSTEM)
   #include <botan/certstor_system.h>
#endif

inline bool value_exists(const std::vector<std::string>& vec,
                         const std::string& val)
   {
   for(size_t i = 0; i != vec.size(); ++i)
      {
      if(vec[i] == val)
         {
         return true;
         }
      }
   return false;
   }

class Basic_Credentials_Manager : public Botan::Credentials_Manager
   {
   public:
      Basic_Credentials_Manager(bool use_system_store,
                                const std::string& ca_path)
         {
         if(ca_path.empty() == false)
            {
            m_certstores.push_back(std::make_shared<Botan::Certificate_Store_In_Memory>(ca_path));
            }

#if defined(BOTAN_HAS_CERTSTOR_SYSTEM)
         if(use_system_store)
            {
            m_certstores.push_back(std::make_shared<Botan::System_Certificate_Store>());
            }
#else
         BOTAN_UNUSED(use_system_store);
#endif
         }

      Basic_Credentials_Manager(Botan::RandomNumberGenerator& rng,
                                const std::string& server_crt,
                                const std::string& server_key)
         {
         Certificate_Info cert;

         cert.key.reset(Botan::PKCS8::load_key(server_key, rng));

         Botan::DataSource_Stream in(server_crt);
         while(!in.end_of_data())
            {
            try
               {
               cert.certs.push_back(Botan::X509_Certificate(in));
               }
            catch(std::exception&)
               {
               }
            }

         // TODO: attempt to validate chain ourselves

         m_creds.push_back(cert);
         }

      std::vector<Botan::Certificate_Store*>
      trusted_certificate_authorities(const std::string& type,
                                      const std::string& /*hostname*/) override
         {
         std::vector<Botan::Certificate_Store*> v;

         // don't ask for client certs
         if(type == "tls-server")
            {
            return v;
            }

         for(auto const& cs : m_certstores)
            {
            v.push_back(cs.get());
            }

         return v;
         }

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& algos,
         const std::string& type,
         const std::string& hostname) override
         {
         BOTAN_UNUSED(type);

         for(auto const& i : m_creds)
            {
            if(std::find(algos.begin(), algos.end(), i.key->algo_name()) == algos.end())
               {
               continue;
               }

            if(hostname != "" && !i.certs[0].matches_dns_name(hostname))
               {
               continue;
               }

            return i.certs;
            }

         return std::vector<Botan::X509_Certificate>();
         }

      Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert,
                                          const std::string& /*type*/,
                                          const std::string& /*context*/) override
         {
         for(auto const& i : m_creds)
            {
            if(cert == i.certs[0])
               {
               return i.key.get();
               }
            }

         return nullptr;
         }

   private:
      struct Certificate_Info
         {
         std::vector<Botan::X509_Certificate> certs;
         std::shared_ptr<Botan::Private_Key> key;
         };

      std::vector<Certificate_Info> m_creds;
      std::vector<std::shared_ptr<Botan::Certificate_Store>> m_certstores;
   };

class TLS_All_Policy final : public Botan::TLS::Policy
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
            "ARIA-256/GCM",
            "ARIA-128/GCM",
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
         return { "ECDSA", "RSA", "DSA", "IMPLICIT" };
         }

      bool allow_tls10() const override { return true; }
      bool allow_tls11() const override { return true; }
      bool allow_tls12() const override { return true; }
   };

inline std::unique_ptr<Botan::TLS::Policy> load_tls_policy(const std::string policy_type)
   {
   std::unique_ptr<Botan::TLS::Policy> policy;

   if(policy_type == "default" || policy_type == "")
      {
      policy.reset(new Botan::TLS::Policy);
      }
   else if(policy_type == "suiteb_128")
      {
      policy.reset(new Botan::TLS::NSA_Suite_B_128);
      }
   else if(policy_type == "suiteb_192" || policy_type == "suiteb")
      {
      policy.reset(new Botan::TLS::NSA_Suite_B_192);
      }
   else if(policy_type == "strict")
      {
      policy.reset(new Botan::TLS::Strict_Policy);
      }
   else if(policy_type == "bsi")
      {
      policy.reset(new Botan::TLS::BSI_TR_02102_2);
      }
   else if(policy_type == "datagram")
      {
      policy.reset(new Botan::TLS::Strict_Policy);
      }
   else if(policy_type == "all" || policy_type == "everything")
      {
      policy.reset(new TLS_All_Policy);
      }
   else
      {
      // assume it's a file
      std::ifstream policy_stream(policy_type);
      if(!policy_stream.good())
         {
         throw Botan_CLI::CLI_Usage_Error("Unknown TLS policy: not a file or known short name");
         }
      policy.reset(new Botan::TLS::Text_Policy(policy_stream));
      }

   return policy;
   }

#endif
