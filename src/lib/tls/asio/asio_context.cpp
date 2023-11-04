/*
 * TLS Context
 * (C) 2024 Jack Lloyd
 *     2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/asio_context.h>

#if defined(BOTAN_HAS_HAS_DEFAULT_TLS_CONTEXT)
   #include <botan/auto_rng.h>
   #include <botan/certstor_system.h>
   #include <botan/tls_session_manager_memory.h>
#endif

namespace Botan::TLS {

#if defined(BOTAN_HAS_HAS_DEFAULT_TLS_CONTEXT)

namespace {

/**
 * A Credentials_Manager that provides the system's certificate store as trust
 * store, if available. Otherwise it defaults to "no trusted certificates".
 */
class Default_Credentials_Manager : public Credentials_Manager {
   public:
      Default_Credentials_Manager() {
         try {
            m_cert_store = std::make_unique<System_Certificate_Store>();
         } catch(const Not_Implemented&) {
            // This platform does not provide an adapter for the system's trust store.
         }
      }

      std::vector<Certificate_Store*> trusted_certificate_authorities(const std::string&, const std::string&) override {
         if(m_cert_store) {
            return {m_cert_store.get()};
         } else {
            return {};
         }
      }

   private:
      std::unique_ptr<Certificate_Store> m_cert_store;
};

}  // namespace

Context::Context(Server_Information server_info) :
      m_credentials_manager(std::make_shared<Default_Credentials_Manager>()),
      m_rng(std::make_shared<AutoSeeded_RNG>()),
      m_session_manager(std::make_shared<Session_Manager_In_Memory>(m_rng)),
      m_policy(std::make_shared<Default_Policy>()),
      m_server_info(std::move(server_info)) {}

#endif

}  // namespace Botan::TLS
