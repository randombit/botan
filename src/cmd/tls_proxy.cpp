/*
* TLS Server Proxy
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_TLS)

#include <iostream>
#include <string>
#include <vector>
#include <thread>

#define _GLIBCXX_HAVE_GTHR_DEFAULT
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <botan/tls_server.h>
#include <botan/x509cert.h>
#include <botan/pkcs8.h>
#include <botan/auto_rng.h>

#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
  #include <botan/tls_session_manager_sqlite.h>
#endif

#include "credentials.h"

using boost::asio::ip::tcp;

namespace Botan {

namespace {

inline void log_exception(const char* where, const std::exception& e)
   {
   std::cout << where << ' ' << e.what() << std::endl;
   }

inline void log_error(const char* where, const boost::system::error_code& error)
   {
   //std::cout << where << ' ' << error.message() << std::endl;
   }

inline void log_binary_message(const char* where, const byte buf[], size_t buf_len)
   {
   //std::cout << where << ' ' << hex_encode(buf, buf_len) << std::endl;
   }

void log_text_message(const char* where,  const byte buf[], size_t buf_len)
   {
   //const char* c = reinterpret_cast<const char*>(buf);
   //std::cout << where << ' ' << std::string(c, c + buf_len)  << std::endl;
   }

class tls_proxy_session : public boost::enable_shared_from_this<tls_proxy_session>
   {
   public:
      enum { readbuf_size = 4 * 1024 };

      typedef boost::shared_ptr<tls_proxy_session> pointer;

      static pointer create(boost::asio::io_service& io,
                            TLS::Session_Manager& session_manager,
                            Credentials_Manager& credentials,
                            TLS::Policy& policy,
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

      tcp::socket& client_socket() { return m_client_socket; }

      void start()
         {
         m_c2p.resize(readbuf_size);

         client_read(boost::system::error_code(), 0); // start read loop
         }

      void stop()
         {
         m_tls.close();
         m_client_socket.close();
         m_server_socket.close();
         }

   private:
      tls_proxy_session(boost::asio::io_service& io,
                        TLS::Session_Manager& session_manager,
                        Credentials_Manager& credentials,
                        TLS::Policy& policy,
                        tcp::resolver::iterator endpoints) :
         m_strand(io),
         m_server_endpoints(endpoints),
         m_client_socket(io),
         m_server_socket(io),
         m_tls(boost::bind(&tls_proxy_session::tls_proxy_write_to_client, this, _1, _2),
               boost::bind(&tls_proxy_session::tls_client_write_to_proxy, this, _1, _2),
               boost::bind(&tls_proxy_session::tls_alert_cb, this, _1, _2, _3),
               boost::bind(&tls_proxy_session::tls_handshake_complete, this, _1),
               session_manager,
               credentials,
               policy,
               m_rng)
         {
         }

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
               log_binary_message("From client", &m_c2p[0], bytes_transferred);
            m_tls.received_data(&m_c2p[0], bytes_transferred);
            }
         catch(std::exception& e)
            {
            log_exception("TLS connection failed", e);
            stop();
            return;
            }

         m_client_socket.async_read_some(
            boost::asio::buffer(&m_c2p[0], m_c2p.size()),
            m_strand.wrap(boost::bind(&tls_proxy_session::client_read, shared_from_this(),
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
         tls_proxy_write_to_client(nullptr, 0); // initiate another write if needed
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

      void tls_client_write_to_proxy(const byte buf[], size_t buf_len)
         {
         // Immediately bounce message to server
         proxy_write_to_server(buf, buf_len);
         }

      void tls_proxy_write_to_client(const byte buf[], size_t buf_len)
         {
         if(buf_len > 0)
            m_p2c_pending.insert(m_p2c_pending.end(), buf, buf + buf_len);

         // no write now active and we still have output pending
         if(m_p2c.empty() && !m_p2c_pending.empty())
            {
            std::swap(m_p2c_pending, m_p2c);

            //log_binary_message("To Client", &m_p2c[0], m_p2c.size());

            boost::asio::async_write(
               m_client_socket,
               boost::asio::buffer(&m_p2c[0], m_p2c.size()),
               m_strand.wrap(boost::bind(
                                &tls_proxy_session::handle_client_write_completion,
                                shared_from_this(),
                                boost::asio::placeholders::error)));
            }
         }

      void proxy_write_to_server(const byte buf[], size_t buf_len)
         {
         if(buf_len > 0)
            m_p2s_pending.insert(m_p2s_pending.end(), buf, buf + buf_len);

         // no write now active and we still have output pending
         if(m_p2s.empty() && !m_p2s_pending.empty())
            {
            std::swap(m_p2s_pending, m_p2s);

            log_text_message("To Server", &m_p2s[0], m_p2s.size());

            boost::asio::async_write(
               m_server_socket,
               boost::asio::buffer(&m_p2s[0], m_p2s.size()),
               m_strand.wrap(boost::bind(
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
         catch(std::exception& e)
            {
            log_exception("TLS connection failed", e);
            stop();
            return;
            }

         m_s2p.resize(readbuf_size);

         m_server_socket.async_read_some(
            boost::asio::buffer(&m_s2p[0], m_s2p.size()),
            m_strand.wrap(boost::bind(&tls_proxy_session::server_read, shared_from_this(),
                                      boost::asio::placeholders::error,
                                      boost::asio::placeholders::bytes_transferred)));
         }

      bool tls_handshake_complete(const TLS::Session& session)
         {
         //std::cout << "Handshake from client complete\n";

         m_hostname = session.server_info().hostname();

         if(m_hostname != "")
            std::cout << "Client requested hostname '" << m_hostname << "'\n";

         async_connect(m_server_socket, m_server_endpoints,
                       [this](boost::system::error_code ec, tcp::resolver::iterator endpoint)
                       {
                       if(ec)
                          {
                          log_error("Server connection", ec);
                          return;
                          }

                       server_read(boost::system::error_code(), 0); // start read loop
                       proxy_write_to_server(nullptr, 0);
                       });
         return true;
         }

      void tls_alert_cb(TLS::Alert alert, const byte[], size_t)
         {
         if(alert.type() == TLS::Alert::CLOSE_NOTIFY)
            {
            m_tls.close();
            return;
            }
         else
            std::cout << "Alert " << alert.type_string() << "\n";
         }

      boost::asio::io_service::strand m_strand;

      tcp::resolver::iterator m_server_endpoints;

      tcp::socket m_client_socket;
      tcp::socket m_server_socket;

      AutoSeeded_RNG m_rng;
      TLS::Server m_tls;
      std::string m_hostname;

      std::vector<byte> m_c2p;
      std::vector<byte> m_p2c;
      std::vector<byte> m_p2c_pending;

      std::vector<byte> m_s2p;
      std::vector<byte> m_p2s;
      std::vector<byte> m_p2s_pending;
   };

class tls_proxy_server
   {
   public:
      typedef tls_proxy_session session;

      tls_proxy_server(boost::asio::io_service& io, unsigned short port,
                       tcp::resolver::iterator endpoints,
                       Credentials_Manager& creds,
                       TLS::Policy& policy,
                       TLS::Session_Manager& session_mgr) :
         m_acceptor(io, tcp::endpoint(tcp::v4(), port)),
         m_server_endpoints(endpoints),
         m_creds(creds),
         m_policy(policy),
         m_session_manager(session_mgr)
         {
         session::pointer new_session = make_session();

         m_acceptor.async_accept(
            new_session->client_socket(),
            boost::bind(
               &tls_proxy_server::handle_accept,
               this,
               new_session,
               boost::asio::placeholders::error)
            );
         }

   private:
      session::pointer make_session()
         {
         return session::create(
            m_acceptor.get_io_service(),
            m_session_manager,
            m_creds,
            m_policy,
            m_server_endpoints
            );
         }

      void handle_accept(session::pointer new_session,
                         const boost::system::error_code& error)
         {
         if (!error)
            {
            new_session->start();

            new_session = make_session();

            m_acceptor.async_accept(
               new_session->client_socket(),
               boost::bind(
                  &tls_proxy_server::handle_accept,
                  this,
                  new_session,
                  boost::asio::placeholders::error)
               );
            }
         }

      tcp::acceptor m_acceptor;
      tcp::resolver::iterator m_server_endpoints;

      Credentials_Manager& m_creds;
      TLS::Policy& m_policy;
      TLS::Session_Manager& m_session_manager;
   };

size_t choose_thread_count()
   {
   size_t result = std::thread::hardware_concurrency();

   if(result)
      return result;

   return 2;
   }

int tls_proxy(int argc, char* argv[])
   {
   if(argc != 6)
      {
      std::cout << "Usage: " << argv[0] << " listen_port target_host target_port server_cert server_key\n";
      return 1;
      }

   const size_t listen_port = to_u32bit(argv[1]);
   const std::string target = argv[2];
   const std::string target_port = argv[3];

   const std::string server_crt = argv[4];
   const std::string server_key = argv[5];

   const size_t num_threads = choose_thread_count(); // make configurable

   AutoSeeded_RNG rng;
   Basic_Credentials_Manager creds(rng, server_crt, server_key);

   TLS::Policy policy; // TODO: Read policy from text file

   try
      {
      boost::asio::io_service io;

      tcp::resolver resolver(io);
      auto server_endpoint_iterator = resolver.resolve({ target, target_port });

#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
      // Todo: make configurable
      const std::string sessions_passphrase = "correct horse battery staple";
      const std::string sessions_db = "sessions.db";
      TLS::Session_Manager_SQLite sessions(sessions_passphrase, rng, sessions_db);
#else
      TLS::Session_Manager_In_Memory sessions(rng);
#endif

      tls_proxy_server server(io, listen_port, server_endpoint_iterator, creds, policy, sessions);

      std::vector<std::shared_ptr<std::thread>> threads;

      for(size_t i = 2; i <= num_threads; ++i)
         threads.push_back(std::make_shared<std::thread>([&io]() { io.run(); }));

      io.run();

      for (size_t i = 0; i < threads.size(); ++i)
         threads[i]->join();
      }
   catch (std::exception& e)
      {
      std::cerr << e.what() << std::endl;
      }

   return 0;
   }

}

}

REGISTER_APP(tls_proxy);

#endif
