#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/tls.h>

#include <memory>

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
         // send data to tls client, e.g., using BSD sockets or boost asio
         BOTAN_UNUSED(data);
      }

      void tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) override {
         // process full TLS record received by tls client, e.g.,
         // by passing it to the application
         BOTAN_UNUSED(seq_no, data);
      }

      void tls_alert(Botan::TLS::Alert alert) override {
         // handle a tls alert received from the tls server
         BOTAN_UNUSED(alert);
      }
};

/**
 * @brief Credentials storage for the tls server.
 *
 * It returns a certificate and the associated private key to
 * authenticate the tls server to the client.
 * TLS client authentication is not requested.
 * See src/lib/tls/credentials_manager.h.
 */
class Server_Credentials : public Botan::Credentials_Manager {
   public:
      Server_Credentials() {
         Botan::DataSource_Stream in("botan.randombit.net.key");
         m_key.reset(Botan::PKCS8::load_key(in).release());
      }

      std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(const std::string& type,
                                                                             const std::string& context) override {
         BOTAN_UNUSED(type, context);
         // if client authentication is required, this function
         // shall return a list of certificates of CAs we trust
         // for tls client certificates, otherwise return an empty list
         return {};
      }

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
         const std::string& type,
         const std::string& context) override {
         BOTAN_UNUSED(cert_key_types, cert_signature_schemes, type, context);

         // return the certificate chain being sent to the tls client
         // e.g., the certificate file "botan.randombit.net.crt"
         return {Botan::X509_Certificate("botan.randombit.net.crt")};
      }

      std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate& cert,
                                                          const std::string& type,
                                                          const std::string& context) override {
         BOTAN_UNUSED(cert, type, context);
         // return the private key associated with the leaf certificate,
         // in this case the one associated with "botan.randombit.net.crt"
         return m_key;
      }

   private:
      std::shared_ptr<Botan::Private_Key> m_key;
};

int main() {
   // prepare all the parameters
   auto callbacks = std::make_shared<Callbacks>();
   auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
   auto session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
   auto creds = std::make_shared<Server_Credentials>();
   auto policy = std::make_shared<Botan::TLS::Strict_Policy>();

   // accept tls connection from client
   Botan::TLS::Server server(callbacks, session_mgr, creds, policy, rng);

   // read data received from the tls client, e.g., using BSD sockets or boost asio
   // and pass it to server.received_data().
   // ...

   // send data to the tls client using server.send()
   // ...

   return 0;
}
