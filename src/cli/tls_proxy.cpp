/*
* TLS Server Proxy
* (C) 2014,2015,2019 Jack Lloyd
* (C) 2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_BOOST_ASIO) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>

#define _GLIBCXX_HAVE_GTHR_DEFAULT
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <botan/internal/os_utils.h>

#include <botan/tls_server.h>
#include <botan/x509cert.h>
#include <botan/pkcs8.h>
#include <botan/hex.h>
#include <botan/rng.h>

#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
   #include <botan/tls_session_manager_sqlite.h>
#endif

#include "tls_helpers.h"

#if BOOST_VERSION >= 107000
#define GET_IO_SERVICE(s) (static_cast<boost::asio::io_context&>((s).get_executor().context()))
#else
#define GET_IO_SERVICE(s) ((s).get_io_service())
#endif

namespace Botan_CLI {

namespace {

using boost::asio::ip::tcp;

void log_exception(const char* where, const std::exception& e)
   {
   std::cout << where << ' ' << e.what() << std::endl;
   }

void log_error(const char* where, const boost::system::error_code& error)
   {
   std::cout << where << ' ' << error.message() << std::endl;
   }

void log_binary_message(const char* where, const uint8_t buf[], size_t buf_len)
   {
   BOTAN_UNUSED(where, buf, buf_len);
   //std::cout << where << ' ' << Botan::hex_encode(buf, buf_len) << std::endl;
   }

void log_text_message(const char* where,  const uint8_t buf[], size_t buf_len)
   {
   BOTAN_UNUSED(where, buf, buf_len);
   //const char* c = reinterpret_cast<const char*>(buf);
   //std::cout << where << ' ' << std::string(c, c + buf_len)  << std::endl;
   }

class ServerStatus
   {
   public:
      ServerStatus(size_t max_clients) : m_max_clients(max_clients), m_clients_serviced(0) {}

      bool should_exit() const
         {
         if(m_max_clients == 0)
            return false;

         return clients_serviced() >= m_max_clients;
         }

      void client_serviced() { m_clients_serviced++; }

      size_t clients_serviced() const { return m_clients_serviced.load(); }
   private:
      size_t m_max_clients;
      std::atomic<size_t> m_clients_serviced;
   };

class tls_proxy_session final : public std::enable_shared_from_this<tls_proxy_session>,
                                public Botan::TLS::Callbacks
   {
   public:
      enum { readbuf_size = 17 * 1024 };

      typedef std::shared_ptr<tls_proxy_session> pointer;

      static pointer create(
         boost::asio::io_service& io,
         Botan::TLS::Session_Manager& session_manager,
         Botan::Credentials_Manager& credentials,
         Botan::TLS::Policy& policy,
         tcp::resolver::iterator endpoints)
         {
         return pointer(
                   new tls_proxy_session(
                      io,
                      session_manager,
                      credentials,
                      policy,
                      endpoints)
                );
         }

      tcp::socket& client_socket()
         {
         return m_client_socket;
         }

      void start()
         {
         m_c2p.resize(readbuf_size);
         client_read(boost::system::error_code(), 0); // start read loop
         }

      void stop()
         {
         if(m_is_closed == false)
            {
            /*
            Don't need to talk to the server anymore
            Client socket is closed during write callback
            */
            m_server_socket.close();
            m_tls.close();
            m_is_closed = true;
            }
         }

   private:
      tls_proxy_session(
         boost::asio::io_service& io,
         Botan::TLS::Session_Manager& session_manager,
         Botan::Credentials_Manager& credentials,
         Botan::TLS::Policy& policy,
         tcp::resolver::iterator endpoints)
         : m_strand(io)
         , m_server_endpoints(endpoints)
         , m_client_socket(io)
         , m_server_socket(io)
         , m_rng(cli_make_rng())
         , m_tls(*this,
                 session_manager,
                 credentials,
                 policy,
                 *m_rng) {}

      void client_read(const boost::system::error_code& error,
                       size_t bytes_transferred)
         {
         if(error)
            {
            log_error("Read failed", error);
            stop();
            return;
            }

         try
            {
            if(!m_tls.is_active())
               {
               log_binary_message("From client", &m_c2p[0], bytes_transferred);
               }
            m_tls.received_data(&m_c2p[0], bytes_transferred);
            }
         catch(Botan::Exception& e)
            {
            log_exception("TLS connection failed", e);
            stop();
            return;
            }

         m_client_socket.async_read_some(
            boost::asio::buffer(&m_c2p[0], m_c2p.size()),
            m_strand.wrap(
               boost::bind(
                  &tls_proxy_session::client_read, shared_from_this(),
                  boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred)));
         }

      void handle_client_write_completion(const boost::system::error_code& error)
         {
         if(error)
            {
            log_error("Client write", error);
            stop();
            return;
            }

         m_p2c.clear();

         if(m_p2c_pending.empty() && m_tls.is_closed())
            {
            m_client_socket.close();
            }
         tls_emit_data(nullptr, 0); // initiate another write if needed
         }

      void handle_server_write_completion(const boost::system::error_code& error)
         {
         if(error)
            {
            log_error("Server write", error);
            stop();
            return;
            }

         m_p2s.clear();
         proxy_write_to_server(nullptr, 0); // initiate another write if needed
         }

      void tls_record_received(uint64_t /*rec_no*/, const uint8_t buf[], size_t buf_len) override
         {
         // Immediately bounce message to server
         proxy_write_to_server(buf, buf_len);
         }

      void tls_emit_data(const uint8_t buf[], size_t buf_len) override
         {
         if(buf_len > 0)
            {
            m_p2c_pending.insert(m_p2c_pending.end(), buf, buf + buf_len);
            }

         // no write now active and we still have output pending
         if(m_p2c.empty() && !m_p2c_pending.empty())
            {
            std::swap(m_p2c_pending, m_p2c);

            log_binary_message("To Client", &m_p2c[0], m_p2c.size());

            boost::asio::async_write(
               m_client_socket,
               boost::asio::buffer(&m_p2c[0], m_p2c.size()),
               m_strand.wrap(
                  boost::bind(
                     &tls_proxy_session::handle_client_write_completion,
                     shared_from_this(),
                     boost::asio::placeholders::error)));
            }
         }

      void proxy_write_to_server(const uint8_t buf[], size_t buf_len)
         {
         if(buf_len > 0)
            {
            m_p2s_pending.insert(m_p2s_pending.end(), buf, buf + buf_len);
            }

         // no write now active and we still have output pending
         if(m_p2s.empty() && !m_p2s_pending.empty())
            {
            std::swap(m_p2s_pending, m_p2s);

            log_text_message("To Server", &m_p2s[0], m_p2s.size());

            boost::asio::async_write(
               m_server_socket,
               boost::asio::buffer(&m_p2s[0], m_p2s.size()),
               m_strand.wrap(
                  boost::bind(
                     &tls_proxy_session::handle_server_write_completion,
                     shared_from_this(),
                     boost::asio::placeholders::error)));
            }
         }

      void server_read(const boost::system::error_code& error,
                       size_t bytes_transferred)
         {
         if(error)
            {
            log_error("Server read failed", error);
            stop();
            return;
            }

         try
            {
            if(bytes_transferred)
               {
               log_text_message("Server to client", &m_s2p[0], m_s2p.size());
               log_binary_message("Server to client", &m_s2p[0], m_s2p.size());
               m_tls.send(&m_s2p[0], bytes_transferred);
               }
            }
         catch(Botan::Exception& e)
            {
            log_exception("TLS connection failed", e);
            stop();
            return;
            }

         m_s2p.resize(readbuf_size);

         m_server_socket.async_read_some(
            boost::asio::buffer(&m_s2p[0], m_s2p.size()),
            m_strand.wrap(
               boost::bind(&tls_proxy_session::server_read, shared_from_this(),
                           boost::asio::placeholders::error,
                           boost::asio::placeholders::bytes_transferred)));
         }

      bool tls_session_established(const Botan::TLS::Session& session) override
         {
         m_hostname = session.server_info().hostname();

         auto onConnect = [this](boost::system::error_code ec, tcp::resolver::iterator /*endpoint*/)
            {
            if(ec)
               {
               log_error("Server connection", ec);
               return;
               }
            server_read(boost::system::error_code(), 0); // start read loop
            proxy_write_to_server(nullptr, 0);
            };
         async_connect(m_server_socket, m_server_endpoints, onConnect);
         return true;
         }

      void tls_alert(Botan::TLS::Alert alert) override
         {
         if(alert.type() == Botan::TLS::Alert::CLOSE_NOTIFY)
            {
            m_tls.close();
            return;
            }
         }

      boost::asio::io_service::strand m_strand;

      tcp::resolver::iterator m_server_endpoints;

      tcp::socket m_client_socket;
      tcp::socket m_server_socket;

      std::unique_ptr<Botan::RandomNumberGenerator> m_rng;
      Botan::TLS::Server m_tls;
      std::string m_hostname;

      std::vector<uint8_t> m_c2p;
      std::vector<uint8_t> m_p2c;
      std::vector<uint8_t> m_p2c_pending;

      std::vector<uint8_t> m_s2p;
      std::vector<uint8_t> m_p2s;
      std::vector<uint8_t> m_p2s_pending;

      bool m_is_closed = false;
   };

class tls_proxy_server final
   {
   public:
      typedef tls_proxy_session session;

      tls_proxy_server(
         boost::asio::io_service& io, unsigned short port,
         tcp::resolver::iterator endpoints,
         Botan::Credentials_Manager& creds,
         Botan::TLS::Policy& policy,
         Botan::TLS::Session_Manager& session_mgr,
         size_t max_clients)
         : m_acceptor(io, tcp::endpoint(tcp::v4(), port))
         , m_server_endpoints(endpoints)
         , m_creds(creds)
         , m_policy(policy)
         , m_session_manager(session_mgr)
         , m_status(max_clients)
         {
         session::pointer new_session = make_session();

         m_acceptor.async_accept(
            new_session->client_socket(),
            boost::bind(
               &tls_proxy_server::handle_accept,
               this,
               new_session,
               boost::asio::placeholders::error));
         }

   private:
      session::pointer make_session()
         {
         return session::create(
                   GET_IO_SERVICE(m_acceptor),
                   m_session_manager,
                   m_creds,
                   m_policy,
                   m_server_endpoints);
         }

      void handle_accept(session::pointer new_session,
                         const boost::system::error_code& error)
         {
         if(!error)
            {
            new_session->start();
            new_session = make_session();

            m_status.client_serviced();

            if(m_status.should_exit() == false)
               {
               m_acceptor.async_accept(
                  new_session->client_socket(),
                  boost::bind(
                     &tls_proxy_server::handle_accept,
                     this,
                     new_session,
                     boost::asio::placeholders::error));
               }
            }
         }

      tcp::acceptor m_acceptor;
      tcp::resolver::iterator m_server_endpoints;

      Botan::Credentials_Manager& m_creds;
      Botan::TLS::Policy& m_policy;
      Botan::TLS::Session_Manager& m_session_manager;
      ServerStatus m_status;
   };

}

class TLS_Proxy final : public Command
   {
   public:
      TLS_Proxy() : Command("tls_proxy listen_port target_host target_port server_cert server_key "
                               "--policy=default --threads=0 --max-clients=0 --session-db= --session-db-pass=") {}

      std::string group() const override
         {
         return "tls";
         }

      std::string description() const override
         {
         return "Proxies requests between a TLS client and a TLS server";
         }

      size_t thread_count() const
         {
         if(size_t t = get_arg_sz("threads"))
            return t;
         if(size_t t = Botan::OS::get_cpu_available())
            return t;
         return 2;
         }

      void go() override
         {
         const uint16_t listen_port = get_arg_u16("listen_port");
         const std::string target = get_arg("target_host");
         const std::string target_port = get_arg("target_port");

         const std::string server_crt = get_arg("server_cert");
         const std::string server_key = get_arg("server_key");

         const size_t num_threads = thread_count();
         const size_t max_clients = get_arg_sz("max-clients");

         Basic_Credentials_Manager creds(rng(), server_crt, server_key);

         auto policy = load_tls_policy(get_arg("policy"));

         boost::asio::io_service io;

         tcp::resolver resolver(io);
         auto server_endpoint_iterator = resolver.resolve({ target, target_port });

         std::unique_ptr<Botan::TLS::Session_Manager> session_mgr;

#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
         const std::string sessions_passphrase = get_passphrase_arg("Session DB passphrase", "session-db-pass");
         const std::string sessions_db = get_arg("session-db");

         if(!sessions_db.empty())
            {
            session_mgr.reset(new Botan::TLS::Session_Manager_SQLite(sessions_passphrase, rng(), sessions_db));
            }
#endif
         if(!session_mgr)
            {
            session_mgr.reset(new Botan::TLS::Session_Manager_In_Memory(rng()));
            }

         tls_proxy_server server(io, listen_port, server_endpoint_iterator, creds, *policy, *session_mgr, max_clients);

         std::vector<std::shared_ptr<std::thread>> threads;

         // run forever... first thread is main calling io.run below
         for(size_t i = 2; i <= num_threads; ++i)
            {
            threads.push_back(std::make_shared<std::thread>([&io]() { io.run(); }));
            }

         io.run();

         for(size_t i = 0; i < threads.size(); ++i)
            {
            threads[i]->join();
            }
         }
   };

BOTAN_REGISTER_COMMAND("tls_proxy", TLS_Proxy);

}

#endif
