/*
* (C) 2014,2015,2019 Jack Lloyd
*     2023           René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CLI_TLS_HELPERS_H_
#define BOTAN_CLI_TLS_HELPERS_H_

#include <botan/credentials_manager.h>
#include <botan/data_src.h>
#include <botan/pkcs8.h>
#include <botan/tls_policy.h>
#include <botan/x509self.h>
#include <fstream>
#include <memory>

#include "cli_exceptions.h"

#if defined(BOTAN_HAS_CERTSTOR_SYSTEM)
   #include <botan/certstor_system.h>
#endif

inline bool value_exists(const std::vector<std::string>& vec, const std::string& val) {
   for(size_t i = 0; i != vec.size(); ++i) {
      if(vec[i] == val) {
         return true;
      }
   }
   return false;
}

class Basic_Credentials_Manager : public Botan::Credentials_Manager {
   protected:
      void load_credentials(const std::string& crt, const std::string& key) {
         Certificate_Info cert;

         Botan::DataSource_Stream key_in(key);
         cert.key = Botan::PKCS8::load_key(key_in);

         Botan::DataSource_Stream in(crt);
         while(!in.end_of_data()) {
            try {
               cert.certs.push_back(Botan::X509_Certificate(in));
            } catch(std::exception&) {}
         }

         // TODO: attempt to validate chain ourselves

         m_creds.push_back(cert);
      }

   public:
      Basic_Credentials_Manager(bool use_system_store,
                                std::string ca_path,
                                std::optional<std::string> client_crt = std::nullopt,
                                std::optional<std::string> client_key = std::nullopt,
                                std::optional<Botan::secure_vector<uint8_t>> psk = std::nullopt,
                                std::optional<std::string> psk_identity = std::nullopt) :
            m_psk(std::move(psk)), m_psk_identity(std::move(psk_identity)) {
         if(ca_path.empty() == false) {
            m_certstores.push_back(std::make_shared<Botan::Certificate_Store_In_Memory>(ca_path));
         }

         BOTAN_ARG_CHECK(client_crt.has_value() == client_key.has_value(),
                         "either provide both client certificate and key or neither");

         if(client_crt.has_value() && client_key.has_value()) {
            load_credentials(client_crt.value(), client_key.value());
         }

#if defined(BOTAN_HAS_CERTSTOR_SYSTEM)
         if(use_system_store) {
            m_certstores.push_back(std::make_shared<Botan::System_Certificate_Store>());
         }
#else
         BOTAN_UNUSED(use_system_store);
#endif
      }

      Basic_Credentials_Manager(const std::string& server_crt,
                                const std::string& server_key,
                                std::optional<Botan::secure_vector<uint8_t>> psk = std::nullopt,
                                std::optional<std::string> psk_identity = std::nullopt) :
            m_psk(std::move(psk)), m_psk_identity(std::move(psk_identity)) {
         load_credentials(server_crt, server_key);
      }

      std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(const std::string& type,
                                                                             const std::string& /*hostname*/) override {
         std::vector<Botan::Certificate_Store*> v;

         // don't ask for client certs
         if(type == "tls-server") {
            return v;
         }

         for(const auto& cs : m_certstores) {
            v.push_back(cs.get());
         }

         return v;
      }

      std::vector<Botan::X509_Certificate> find_cert_chain(
         const std::vector<std::string>& algos,
         const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
         const std::vector<Botan::X509_DN>& acceptable_cas,
         const std::string& type,
         const std::string& hostname) override {
         BOTAN_UNUSED(cert_signature_schemes);

         if(type == "tls-client") {
            for(const auto& dn : acceptable_cas) {
               for(const auto& cred : m_creds) {
                  if(dn == cred.certs[0].issuer_dn()) {
                     return cred.certs;
                  }
               }
            }
         } else if(type == "tls-server") {
            for(const auto& i : m_creds) {
               if(std::find(algos.begin(), algos.end(), i.key->algo_name()) == algos.end()) {
                  continue;
               }

               if(hostname != "" && !i.certs[0].matches_dns_name(hostname)) {
                  continue;
               }

               return i.certs;
            }
         }

         return {};
      }

      std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate& cert,
                                                          const std::string& /*type*/,
                                                          const std::string& /*context*/) override {
         for(const auto& i : m_creds) {
            if(cert == i.certs[0]) {
               return i.key;
            }
         }

         return nullptr;
      }

      std::string psk_identity(const std::string& type,
                               const std::string& context,
                               const std::string& identity_hint) override {
         return (m_psk_identity && (type == "tls-client" || type == "tls-server"))
                   ? m_psk_identity.value()
                   : Botan::Credentials_Manager::psk_identity(type, context, identity_hint);
      }

      std::vector<Botan::TLS::ExternalPSK> find_preshared_keys(
         std::string_view host,
         Botan::TLS::Connection_Side peer_type,
         const std::vector<std::string>& ids = {},
         const std::optional<std::string>& prf = std::nullopt) override {
         if(!m_psk.has_value() || !m_psk_identity.has_value()) {
            return Botan::Credentials_Manager::find_preshared_keys(host, peer_type, ids, prf);
         }

         std::vector<Botan::TLS::ExternalPSK> psks;

         const bool prf_matches = !prf.has_value() || m_psk_prf == prf.value();
         const bool id_matches = ids.empty() || std::find(ids.begin(), ids.end(), m_psk_identity.value()) != ids.end();

         if(prf_matches && id_matches) {
            psks.emplace_back(m_psk_identity.value(), m_psk_prf, m_psk.value());
         }

         return psks;
      }

   private:
      struct Certificate_Info {
            std::vector<Botan::X509_Certificate> certs;
            std::shared_ptr<Botan::Private_Key> key;
      };

      std::vector<Certificate_Info> m_creds;
      std::vector<std::shared_ptr<Botan::Certificate_Store>> m_certstores;
      std::optional<Botan::secure_vector<uint8_t>> m_psk;
      std::optional<std::string> m_psk_identity;
      std::string m_psk_prf;
};

class TLS_All_Policy final : public Botan::TLS::Policy {
   public:
      std::vector<std::string> allowed_ciphers() const override {
         return std::vector<std::string>{"ChaCha20Poly1305",
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
                                         "SEED",
                                         "3DES"};
      }

      std::vector<std::string> allowed_key_exchange_methods() const override {
         return {"ECDHE_PSK", "DHE_PSK", "PSK", "ECDH", "DH", "RSA"};
      }

      std::vector<std::string> allowed_signature_methods() const override {
         return {"ECDSA", "RSA", "DSA", "IMPLICIT"};
      }

      bool allow_tls12() const override { return true; }
};

inline std::shared_ptr<Botan::TLS::Policy> load_tls_policy(const std::string policy_type) {
   if(policy_type == "default" || policy_type == "") {
      return std::make_shared<Botan::TLS::Policy>();
   } else if(policy_type == "suiteb_128") {
      return std::make_shared<Botan::TLS::NSA_Suite_B_128>();
   } else if(policy_type == "suiteb_192" || policy_type == "suiteb") {
      return std::make_shared<Botan::TLS::NSA_Suite_B_192>();
   } else if(policy_type == "strict") {
      return std::make_shared<Botan::TLS::Strict_Policy>();
   } else if(policy_type == "bsi") {
      return std::make_shared<Botan::TLS::BSI_TR_02102_2>();
   } else if(policy_type == "datagram") {
      return std::make_shared<Botan::TLS::Strict_Policy>();
   } else if(policy_type == "all" || policy_type == "everything") {
      return std::make_shared<TLS_All_Policy>();
   }

   // if something we don't recognize, assume it's a file
   std::ifstream policy_stream(policy_type);
   if(!policy_stream.good()) {
      throw Botan_CLI::CLI_Usage_Error("Unknown TLS policy: not a file or known short name");
   }
   return std::make_shared<Botan::TLS::Text_Policy>(policy_stream);
}

#endif
