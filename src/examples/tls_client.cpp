#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <botan/certstor_system.h>
#include <botan/tls.h>

/**
 * @brief Callbacks invoked by TLS::Channel.
 *
 * Botan::TLS::Callbacks is an abstract class.
 * For improved readability, only the functions that are mandatory
 * to implement are listed here. See src/lib/tls/tls_callbacks.h.
 */
class Callbacks : public Botan::TLS::Callbacks {
   public:
      void tls_emit_data(std::span<const uint8_t> data) override {
         // send data to tls server, e.g., using BSD sockets or boost asio
         BOTAN_UNUSED(data);
      }

      void tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) override {
         // process full TLS record received by tls server, e.g.,
         // by passing it to the application
         BOTAN_UNUSED(seq_no, data);
      }

      void tls_alert(Botan::TLS::Alert alert) override {
         // handle a tls alert received from the tls server
         BOTAN_UNUSED(alert);
      }
};

/**
 * @brief Credentials storage for the tls client.
 *
 * It returns a list of trusted CA certificates.
 * Here we base trust on the system managed trusted CA list.
 * TLS client authentication is disabled. See src/lib/tls/credentials_manager.h.
 */
class Client_Credentials : public Botan::Credentials_Manager {
   public:
      std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(const std::string& type,
                                                                             const std::string& context) override {
         BOTAN_UNUSED(type, context);
         // return a list of certificates of CAs we trust for tls server certificates
         // ownership of the pointers remains with Credentials_Manager
         return {&m_cert_store};
      }

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
         const std::string& type,
         const std::string& context) override {
         BOTAN_UNUSED(cert_key_types, cert_signature_schemes, type, context);

         // when using tls client authentication (optional), return
         // a certificate chain being sent to the tls server,
         // else an empty list
         return {};
      }

      std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate& cert,
                                                          const std::string& type,
                                                          const std::string& context) override {
         BOTAN_UNUSED(cert, type, context);
         // when returning a chain in cert_chain(), return the private key
         // associated with the leaf certificate here
         return nullptr;
      }

   private:
      Botan::System_Certificate_Store m_cert_store;
};

int main() {
   // prepare all the parameters
   auto callbacks = std::make_shared<Callbacks>();
   auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
   auto session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
   auto creds = std::make_shared<Client_Credentials>();
   auto policy = std::make_shared<Botan::TLS::Strict_Policy>();

   // open the tls connection
   Botan::TLS::Client client(callbacks,
                             session_mgr,
                             creds,
                             policy,
                             rng,
                             Botan::TLS::Server_Information("botan.randombit.net", 443),
                             Botan::TLS::Protocol_Version::TLS_V12);

   while(!client.is_closed()) {
      // read data received from the tls server, e.g., using BSD sockets or boost asio
      // ...

      // send data to the tls server using client.send()
   }

   return 0;
}
