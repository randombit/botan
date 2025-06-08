/*
* TLS Server Proxy
* (C) 2014,2015,2019 Jack Lloyd
* (C) 2016 Matthias Gierlings
* (C) 2023 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_BOOST_ASIO) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

   #include <atomic>
   #include <iostream>
   #include <string>
   #include <thread>
   #include <utility>
   #include <vector>

   #include <boost/asio.hpp>
   #include <boost/bind.hpp>

   #include <botan/hex.h>
   #include <botan/pkcs8.h>
   #include <botan/rng.h>
   #include <botan/tls_server.h>
   #include <botan/tls_session_manager_memory.h>
   #include <botan/x509cert.h>

   #if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
      #include <botan/tls_session_manager_sqlite.h>
   #endif

   #if defined(BOTAN_HAS_OS_UTILS)
      #include <botan/internal/os_utils.h>
   #endif

   #include "tls_helpers.h"

namespace Botan_CLI {

namespace {

using boost::asio::ip::tcp;

template <typename T>
boost::asio::io_context& get_io_service(T& s) {
   #if BOOST_VERSION >= 107000
   //NOLINTNEXTLINE(*-type-static-cast-downcast)
   return static_cast<boost::asio::io_context&>((s).get_executor().context());
   #else
   return s.get_io_service();
   #endif
}

void log_info(const std::string& msg) {
   std::cout << msg << std::endl;
}

void log_exception(const char* where, const std::exception& e) {
   std::cout << where << ' ' << e.what() << std::endl;
}

void log_error(const char* where, const boost::system::error_code& error) {
   std::cout << where << ' ' << error.message() << std::endl;
}

void log_error(const char* msg) {
   std::cout << msg << std::endl;
}

void log_binary_message(const char* where, const uint8_t buf[], size_t buf_len) {
   BOTAN_UNUSED(where, buf, buf_len);
   //std::cout << where << ' ' << Botan::hex_encode(buf, buf_len) << std::endl;
}

void log_text_message(const char* where, const uint8_t buf[], size_t buf_len) {
   BOTAN_UNUSED(where, buf, buf_len);
   //const char* c = reinterpret_cast<const char*>(buf);
   //std::cout << where << ' ' << std::string(c, c + buf_len)  << std::endl;
}

class ServerStatus {
   public:
      ServerStatus(size_t max_clients) : m_max_clients(max_clients), m_clients_serviced(0) {}

      bool should_exit() const {
         if(m_max_clients == 0) {
            return false;
         }

         return clients_serviced() >= m_max_clients;
      }

      void client_serviced() { m_clients_serviced++; }

      size_t clients_serviced() const { return m_clients_serviced.load(); }

   private:
      size_t m_max_clients;
      std::atomic<size_t> m_clients_serviced;
};

class tls_proxy_session final : public std::enable_shared_from_this<tls_proxy_session>,
                                public Botan::TLS::Callbacks {
   public:
      static constexpr size_t readbuf_size = 17 * 1024;

      typedef std::shared_ptr<tls_proxy_session> pointer;

      static pointer create(boost::asio::io_context& io,
                            const std::shared_ptr<Botan::TLS::Session_Manager>& session_manager,
                            const std::shared_ptr<Botan::Credentials_Manager>& credentials,
                            const std::shared_ptr<Botan::TLS::Policy>& policy,
                            const tcp::resolver::results_type& endpoints) {
         auto session = std::make_shared<tls_proxy_session>(io, endpoints);

         // Defer the setup of the TLS server to make use of
         // shared_from_this() which wouldn't work in the c'tor.
         session->setup(session_manager, credentials, policy);

         return session;
      }

      tcp::socket& client_socket() { return m_client_socket; }

      void start() {
         m_c2p.resize(readbuf_size);
         client_read(boost::system::error_code(), 0);  // start read loop
      }

      void stop() {
         if(m_is_closed == false) {
            /*
            Don't need to talk to the server anymore
            Client socket is closed during write callback
            */
            m_server_socket.close();
            m_tls->close();

            // Need to explicitly destroy the TLS::Server object to break the
            // circular ownership of shared_from_this() and the shared_ptr of
            // this kept inside the TLS::Channel.
            m_tls.reset();
            m_is_closed = true;
         }
      }

      tls_proxy_session(boost::asio::io_context& io, tcp::resolver::results_type endpoints) :
            m_strand(io),
            m_server_endpoints(std::move(endpoints)),
            m_client_socket(io),
            m_server_socket(io),
            m_rng(cli_make_rng()) {}

   private:
      void setup(const std::shared_ptr<Botan::TLS::Session_Manager>& session_manager,
                 const std::shared_ptr<Botan::Credentials_Manager>& credentials,
                 const std::shared_ptr<Botan::TLS::Policy>& policy) {
         m_tls = std::make_unique<Botan::TLS::Server>(shared_from_this(), session_manager, credentials, policy, m_rng);
      }

      void client_read(const boost::system::error_code& error, size_t bytes_transferred) {
         if(error) {
            log_error("Read failed", error);
            stop();
            return;
         }

         if(m_is_closed) {
            log_error("Received client data after close");
            return;
         }

         try {
            if(!m_tls->is_active()) {
               log_binary_message("From client", &m_c2p[0], bytes_transferred);
            }
            m_tls->received_data(&m_c2p[0], bytes_transferred);
         } catch(Botan::Exception& e) {
            log_exception("TLS connection failed", e);
            stop();
            return;
         }

         m_client_socket.async_read_some(boost::asio::buffer(&m_c2p[0], m_c2p.size()),
                                         m_strand.wrap(boost::bind(&tls_proxy_session::client_read,
                                                                   shared_from_this(),
                                                                   boost::asio::placeholders::error,
                                                                   boost::asio::placeholders::bytes_transferred)));
      }

      void handle_client_write_completion(const boost::system::error_code& error) {
         if(error) {
            log_error("Client write", error);
            stop();
            return;
         }

         m_p2c.clear();

         if(m_p2c_pending.empty() && (!m_tls || m_tls->is_closed())) {
            m_client_socket.close();
         }
         tls_emit_data({});  // initiate another write if needed
      }

      void handle_server_write_completion(const boost::system::error_code& error) {
         if(error) {
            log_error("Server write", error);
            stop();
            return;
         }

         m_p2s.clear();
         proxy_write_to_server({});  // initiate another write if needed
      }

      void tls_record_received(uint64_t /*rec_no*/, std::span<const uint8_t> buf) override {
         // Immediately bounce message to server
         proxy_write_to_server(buf);
      }

      void tls_emit_data(std::span<const uint8_t> buf) override {
         if(!buf.empty()) {
            m_p2c_pending.insert(m_p2c_pending.end(), buf.begin(), buf.end());
         }

         // no write now active and we still have output pending
         if(m_p2c.empty() && !m_p2c_pending.empty()) {
            std::swap(m_p2c_pending, m_p2c);

            log_binary_message("To Client", &m_p2c[0], m_p2c.size());

            boost::asio::async_write(m_client_socket,
                                     boost::asio::buffer(&m_p2c[0], m_p2c.size()),
                                     m_strand.wrap(boost::bind(&tls_proxy_session::handle_client_write_completion,
                                                               shared_from_this(),
                                                               boost::asio::placeholders::error)));
         }
      }

      void proxy_write_to_server(std::span<const uint8_t> buf) {
         if(!buf.empty()) {
            m_p2s_pending.insert(m_p2s_pending.end(), buf.begin(), buf.end());
         }

         // no write now active and we still have output pending
         if(m_p2s.empty() && !m_p2s_pending.empty()) {
            std::swap(m_p2s_pending, m_p2s);

            log_text_message("To Server", &m_p2s[0], m_p2s.size());

            boost::asio::async_write(m_server_socket,
                                     boost::asio::buffer(&m_p2s[0], m_p2s.size()),
                                     m_strand.wrap(boost::bind(&tls_proxy_session::handle_server_write_completion,
                                                               shared_from_this(),
                                                               boost::asio::placeholders::error)));
         }
      }

      void server_read(const boost::system::error_code& error, size_t bytes_transferred) {
         if(error) {
            log_error("Server read failed", error);
            stop();
            return;
         }

         try {
            if(bytes_transferred) {
               log_text_message("Server to client", &m_s2p[0], m_s2p.size());
               log_binary_message("Server to client", &m_s2p[0], m_s2p.size());
               m_tls->send(&m_s2p[0], bytes_transferred);
            }
         } catch(Botan::Exception& e) {
            log_exception("TLS connection failed", e);
            stop();
            return;
         }

         m_s2p.resize(readbuf_size);

         m_server_socket.async_read_some(boost::asio::buffer(&m_s2p[0], m_s2p.size()),
                                         m_strand.wrap(boost::bind(&tls_proxy_session::server_read,
                                                                   shared_from_this(),
                                                                   boost::asio::placeholders::error,
                                                                   boost::asio::placeholders::bytes_transferred)));
      }

      void tls_session_activated() override {
         auto onConnect = [self = weak_from_this()](boost::system::error_code ec,
                                                    const tcp::resolver::results_type::iterator& /*endpoint*/) {
            if(ec) {
               log_error("Server connection", ec);
               return;
            }

            if(auto ptr = self.lock()) {
               ptr->server_read(boost::system::error_code(), 0);  // start read loop
               ptr->proxy_write_to_server({});
            } else {
               log_error("Server connection established, but client session already closed");
               return;
            }
         };
         async_connect(m_server_socket, m_server_endpoints.begin(), m_server_endpoints.end(), onConnect);
      }

      void tls_session_established(const Botan::TLS::Session_Summary& session) override {
         m_hostname = session.server_info().hostname();
      }

      void tls_alert(Botan::TLS::Alert alert) override {
         if(alert.type() == Botan::TLS::Alert::CloseNotify) {
            m_tls->close();
            return;
         }
      }

      boost::asio::io_context::strand m_strand;

      tcp::resolver::results_type m_server_endpoints;

      tcp::socket m_client_socket;
      tcp::socket m_server_socket;

      std::shared_ptr<Botan::RandomNumberGenerator> m_rng;
      std::unique_ptr<Botan::TLS::Server> m_tls;
      std::string m_hostname;

      std::vector<uint8_t> m_c2p;
      std::vector<uint8_t> m_p2c;
      std::vector<uint8_t> m_p2c_pending;

      std::vector<uint8_t> m_s2p;
      std::vector<uint8_t> m_p2s;
      std::vector<uint8_t> m_p2s_pending;

      bool m_is_closed = false;
};

class tls_proxy_server final {
   public:
      typedef tls_proxy_session session;

      tls_proxy_server(boost::asio::io_context& io,
                       unsigned short port,
                       tcp::resolver::results_type endpoints,
                       std::shared_ptr<Botan::Credentials_Manager> creds,
                       std::shared_ptr<Botan::TLS::Policy> policy,
                       std::shared_ptr<Botan::TLS::Session_Manager> session_mgr,
                       size_t max_clients) :
            m_acceptor(io, tcp::endpoint(tcp::v4(), port)),
            m_server_endpoints(std::move(endpoints)),
            m_creds(std::move(creds)),
            m_policy(std::move(policy)),
            m_session_manager(std::move(session_mgr)),
            m_status(max_clients) {
         log_info("Listening for new connections on port " + std::to_string(port));
         serve_one_session();
      }

   private:
      session::pointer make_session() {
         return session::create(get_io_service(m_acceptor), m_session_manager, m_creds, m_policy, m_server_endpoints);
      }

      void serve_one_session() {
         session::pointer new_session = make_session();

         m_acceptor.async_accept(
            new_session->client_socket(),
            boost::bind(&tls_proxy_server::handle_accept, this, new_session, boost::asio::placeholders::error));
      }

      void handle_accept(const session::pointer& new_session, const boost::system::error_code& error) {
         if(!error) {
            new_session->start();
            m_status.client_serviced();

            if(!m_status.should_exit()) {
               serve_one_session();
            }
         }
      }

      tcp::acceptor m_acceptor;
      tcp::resolver::results_type m_server_endpoints;

      std::shared_ptr<Botan::Credentials_Manager> m_creds;
      std::shared_ptr<Botan::TLS::Policy> m_policy;
      std::shared_ptr<Botan::TLS::Session_Manager> m_session_manager;
      ServerStatus m_status;
};

}  // namespace

class TLS_Proxy final : public Command {
   public:
      TLS_Proxy() :
            Command(
               "tls_proxy listen_port target_host target_port server_cert server_key "
               "--policy=default --threads=0 --max-clients=0 --session-db= --session-db-pass=") {}

      std::string group() const override { return "tls"; }

      std::string description() const override { return "Proxies requests between a TLS client and a TLS server"; }

      size_t thread_count() const {
         if(size_t t = get_arg_sz("threads")) {
            return t;
         }
   #if defined(BOTAN_HAS_OS_UTILS)
         if(size_t t = Botan::OS::get_cpu_available()) {
            return t;
         }
   #endif
         return 2;
      }

      void go() override {
         const uint16_t listen_port = get_arg_u16("listen_port");
         const std::string target = get_arg("target_host");
         const std::string target_port = get_arg("target_port");

         const std::string server_crt = get_arg("server_cert");
         const std::string server_key = get_arg("server_key");

         const size_t num_threads = thread_count();
         const size_t max_clients = get_arg_sz("max-clients");

         auto creds = std::make_shared<Basic_Credentials_Manager>(server_crt, server_key);

         auto policy = load_tls_policy(get_arg("policy"));

         boost::asio::io_context io;

         tcp::resolver resolver(io);
         auto server_endpoint_iterator = resolver.resolve(target, target_port);

         std::shared_ptr<Botan::TLS::Session_Manager> session_mgr;

   #if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
         const std::string sessions_passphrase = get_passphrase_arg("Session DB passphrase", "session-db-pass");
         const std::string sessions_db = get_arg("session-db");

         if(!sessions_db.empty()) {
            session_mgr =
               std::make_shared<Botan::TLS::Session_Manager_SQLite>(sessions_passphrase, rng_as_shared(), sessions_db);
         }
   #endif
         if(!session_mgr) {
            session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng_as_shared());
         }

         tls_proxy_server server(io, listen_port, server_endpoint_iterator, creds, policy, session_mgr, max_clients);

         std::vector<std::shared_ptr<std::thread>> threads;

         // run forever... first thread is main calling io.run below
         for(size_t i = 2; i <= num_threads; ++i) {
            threads.push_back(std::make_shared<std::thread>([&io]() { io.run(); }));
         }

         io.run();

         for(size_t i = 0; i < threads.size(); ++i) {
            threads[i]->join();
         }
      }
};

BOTAN_REGISTER_COMMAND("tls_proxy", TLS_Proxy);

}  // namespace Botan_CLI

#endif
