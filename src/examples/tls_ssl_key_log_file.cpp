#include <condition_variable>
#include <fstream>
#include <iostream>
#include <thread>

#include <botan/auto_rng.h>
#include <botan/certstor_system.h>
#include <botan/credentials_manager.h>
#include <botan/data_src.h>
#include <botan/hex.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_channel.h>
#include <botan/tls_client.h>
#include <botan/tls_policy.h>
#include <botan/tls_server.h>
#include <botan/tls_session_manager_memory.h>

#if defined(BOTAN_TARGET_OS_HAS_SOCKETS)
   #include <arpa/inet.h>
   #include <netinet/in.h>
   #include <sys/ioctl.h>
   #include <sys/socket.h>
#endif

namespace {

constexpr uint32_t SERVER_PORT = 5060;
constexpr uint32_t CLIENT_PORT = 5070;

class Client_Credential : public Botan::Credentials_Manager {
   public:
      Client_Credential() = default;

      std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(const std::string&,
                                                                             const std::string&) override {
         return {&m_cert_store};
      }

   private:
      Botan::System_Certificate_Store m_cert_store;
};

class Server_Credential : public Botan::Credentials_Manager {
   public:
      Server_Credential() {
         {
            Botan::DataSource_Stream in("botan.randombit.net.key");
            m_key.reset(Botan::PKCS8::load_key(in).release());
         }
         {
            Botan::DataSource_Stream in("botan.randombit.net.crt");
            while(true) {
               try {
                  certificates.push_back(Botan::X509_Certificate(in));
               } catch(const Botan::Exception&) {
                  break;
               }
            }
         }
      }

      std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(const std::string&,
                                                                             const std::string&) override {
         return {&m_cert_store};
      }

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
         const std::string& type,
         const std::string& context) override {
         BOTAN_UNUSED(cert_signature_schemes, type, context);

         // return the certificate chain being sent to the tls client
         // e.g., the certificate file "botan.randombit.net.crt"
         std::vector<Botan::X509_Certificate> certs;
         for(auto& cert : certificates) {
            std::string algorithm = cert.subject_public_key()->algo_name();
            for(auto& key : cert_key_types) {
               if(algorithm == key) {
                  certs.push_back(cert);
               }
            }
         }
         return certs;
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
      Botan::System_Certificate_Store m_cert_store;
      std::shared_ptr<Botan::Private_Key> m_key;
      std::vector<Botan::X509_Certificate> certificates;
};

class Allow_Secrets_Policy : public Botan::TLS::Datagram_Policy {
   public:
      bool allow_ssl_key_log_file() const override { return true; }
};

class BotanTLSCallbacksProxy : public Botan::TLS::Callbacks {
      Botan::TLS::Callbacks& parent;

   public:
      BotanTLSCallbacksProxy(Botan::TLS::Callbacks& callbacks) : parent(callbacks) {}

      void tls_emit_data(std::span<const uint8_t> data) override { parent.tls_emit_data(data); }

      void tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) override { BOTAN_UNUSED(seq_no, data); }

      void tls_alert(Botan::TLS::Alert alert) override { BOTAN_UNUSED(alert); }

      void tls_ssl_key_log_data(std::string_view label,
                                std::span<const uint8_t> client_random,
                                std::span<const uint8_t> secret) const override {
         parent.tls_ssl_key_log_data(label, client_random, secret);
      }

      void tls_session_activated() override { parent.tls_session_activated(); }
};

class DtlsConnection : public Botan::TLS::Callbacks {
      int fd;
#if defined(BOTAN_TARGET_OS_HAS_SOCKETS)
      sockaddr_in remote_addr;
#endif
      std::unique_ptr<Botan::TLS::Channel> dtls_channel;
      std::function<void()> activated_callback;

   public:
      DtlsConnection(const std::string& r_addr, int r_port, int socket, bool is_server) : fd(socket) {
#if defined(BOTAN_TARGET_OS_HAS_SOCKETS)
         remote_addr.sin_family = AF_INET;
         inet_aton(r_addr.c_str(), &remote_addr.sin_addr);
         remote_addr.sin_port = htons(r_port);
#endif
         auto tls_callbacks_proxy = std::make_shared<BotanTLSCallbacksProxy>(*this);
         auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
         auto session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
         if(is_server) {
            auto policy = std::make_shared<Allow_Secrets_Policy>();
            auto creds = std::make_shared<Server_Credential>();
            dtls_channel =
               std::make_unique<Botan::TLS::Server>(tls_callbacks_proxy, session_mgr, creds, policy, rng, true);
         } else {
            auto policy = std::make_shared<Botan::TLS::Datagram_Policy>();
            auto creds = std::make_shared<Client_Credential>();
            dtls_channel =
               std::make_unique<Botan::TLS::Client>(tls_callbacks_proxy,
                                                    session_mgr,
                                                    creds,
                                                    policy,
                                                    rng,
                                                    Botan::TLS::Server_Information("127.0.0.1", SERVER_PORT),
                                                    Botan::TLS::Protocol_Version::DTLS_V12);
         }
      }

      void tls_emit_data(std::span<const uint8_t> data) override {
#if defined(BOTAN_TARGET_OS_HAS_SOCKETS)
         sendto(fd, data.data(), data.size(), 0, reinterpret_cast<const sockaddr*>(&remote_addr), sizeof(sockaddr_in));
#else
         // send data to the other side
         // ...
#endif
      }

      void tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) override { BOTAN_UNUSED(seq_no, data); }

      void tls_alert(Botan::TLS::Alert alert) override { BOTAN_UNUSED(alert); }

      void tls_session_activated() override {
         std::cout << "************ on_dtls_connect() ***********" << std::endl;
         activated_callback();
      }

      void tls_ssl_key_log_data(std::string_view label,
                                std::span<const uint8_t> client_random,
                                std::span<const uint8_t> secret) const override {
         std::ofstream stream;
         stream.open("test.skl", std::ofstream::out | std::ofstream::app);
         stream << label << " " << Botan::hex_encode(client_random.data(), client_random.size()) << " "
                << Botan::hex_encode(secret.data(), secret.size()) << std::endl;
         stream.close();
      }

      void received_data(std::span<const uint8_t> data) { dtls_channel->received_data(data); }

      void set_activated_callback(std::function<void()> callback) { activated_callback = std::move(callback); }

      void close() const {
         if(fd) {
#if defined(BOTAN_TARGET_OS_HAS_SOCKETS)
            shutdown(fd, SHUT_RDWR);
            ::close(fd);
#endif
         }
      }
};

void server_proc(const std::function<void(std::shared_ptr<DtlsConnection> conn)>& conn_callback) {
   std::cout << "Start Server" << std::endl;

   int fd = 0;
#if defined(BOTAN_TARGET_OS_HAS_SOCKETS)
   fd = socket(AF_INET, SOCK_DGRAM, 0);
   if(fd == -1) {
      return;
   }
   int true_opt = 1;
   if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, static_cast<void*>(&true_opt), sizeof(true_opt)) == -1) {
      return;
   }
   sockaddr_in addr;
   addr.sin_family = AF_INET;
   addr.sin_port = htons(SERVER_PORT);
   inet_aton("127.0.0.1", &addr.sin_addr);
   if(bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(sockaddr_in)) == -1) {
      return;
   }
   sockaddr_in fromaddr;
   fromaddr.sin_family = AF_INET;
   socklen_t len = sizeof(sockaddr_in);
#else
   // create BSD UDP socket and bind it on SERVER_PORT
   // ...
#endif

   auto connection = std::make_shared<DtlsConnection>("127.0.0.1", CLIENT_PORT, fd, true);
   conn_callback(connection);

#if defined(BOTAN_TARGET_OS_HAS_SOCKETS)
   static uint8_t data[8192];
   ssize_t recvlen = 0;
   while((recvlen = recvfrom(fd, data, sizeof(data), 0, reinterpret_cast<sockaddr*>(&fromaddr), &len)) > 0) {
      connection->received_data(std::span(data, recvlen));
   }
#else
   // read data received from the tls client, e.g., using BSD sockets
   // and pass it to connection->received_data.
   // ...
#endif

   std::cout << "Server closed" << std::endl;
}

void client_proc(const std::function<void(std::shared_ptr<DtlsConnection> conn)>& conn_callback) {
   std::cout << "Start Client" << std::endl;

   int fd = 0;
#if defined(BOTAN_TARGET_OS_HAS_SOCKETS)
   fd = socket(AF_INET, SOCK_DGRAM, 0);
   if(fd == -1) {
      return;
   }
   int true_opt = 1;
   if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, static_cast<void*>(&true_opt), sizeof(true_opt)) == -1) {
      return;
   }
   sockaddr_in addr;
   addr.sin_family = AF_INET;
   addr.sin_port = htons(CLIENT_PORT);
   inet_aton("127.0.0.1", &addr.sin_addr);
   if(bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(sockaddr_in)) == -1) {
      return;
   }
   sockaddr_in fromaddr;
   fromaddr.sin_family = AF_INET;
   socklen_t len = sizeof(sockaddr_in);
#else
   // create BSD UDP socket and bind it on CLIENT_PORT
   // ...
#endif

   auto connection = std::make_shared<DtlsConnection>("127.0.0.1", SERVER_PORT, fd, false);
   conn_callback(connection);
#if defined(BOTAN_TARGET_OS_HAS_SOCKETS)
   static uint8_t data[8192];
   ssize_t recvlen = 0;
   while((recvlen = recvfrom(fd, data, sizeof(data), 0, reinterpret_cast<sockaddr*>(&fromaddr), &len)) > 0) {
      connection->received_data(std::span(data, recvlen));
   }
#else
   // read data received from the tls server, e.g., using BSD sockets
   // and pass it to connection->received_data.
   // ...
#endif

   std::cout << "Client closed" << std::endl;
}

}  // namespace

int main() {
   std::mutex m;
   std::condition_variable conn_cond;
   std::vector<std::shared_ptr<DtlsConnection>> connections;
   std::thread server(server_proc, [&](std::shared_ptr<DtlsConnection> conn) {
      std::lock_guard lk(m);
      connections.push_back(std::move(conn));
      if(connections.size() == 2) {
         conn_cond.notify_one();
      }
   });
   std::thread client(client_proc, [&](std::shared_ptr<DtlsConnection> conn) {
      std::lock_guard lk(m);
      connections.push_back(std::move(conn));
      if(connections.size() == 2) {
         conn_cond.notify_one();
      }
   });
   {
      std::unique_lock lk(m);
      conn_cond.wait(lk);
   }

   std::vector<bool> activated;
   for(auto& conn : connections) {
      conn->set_activated_callback([&]() {
         activated.push_back(true);
         if(activated.size() == 2) {
            conn_cond.notify_one();
         }
      });
   }

   {
      std::unique_lock lk(m);
      conn_cond.wait(lk);
   }

   for(auto& conn : connections) {
      conn->close();
   }

   client.join();
   server.join();
   return 0;
}
