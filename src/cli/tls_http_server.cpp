/*
* (C) 2014,2015,2017 Jack Lloyd
* (C) 2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_BOOST_ASIO) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <thread>

#define _GLIBCXX_HAVE_GTHR_DEFAULT
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <botan/tls_server.h>
#include <botan/tls_messages.h>
#include <botan/x509cert.h>
#include <botan/pkcs8.h>
#include <botan/version.h>
#include <botan/hex.h>

#if defined(BOTAN_HAS_SYSTEM_RNG)
   #include <botan/system_rng.h>
#else
   #include <botan/auto_rng.h>
#endif

#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
   #include <botan/tls_session_manager_sqlite.h>
#endif

#include "credentials.h"

namespace Botan_CLI {

namespace {

using boost::asio::ip::tcp;

inline void log_exception(const char* where, const std::exception& e)
   {
   std::cout << where << ' ' << e.what() << std::endl;
   }

/*
* This is an incomplete and highly buggy HTTP request parser. It is just
* barely sufficient to handle a GET request sent by a browser.
*/
class HTTP_Parser
   {
   public:
      class Request
         {
         public:
            const std::string& verb() const { return m_verb; }
            const std::string& location() const { return m_location; }
            const std::map<std::string, std::string>& headers() const { return m_headers; }

            Request(const std::string& verb,
                    const std::string& location,
                    const std::map<std::string, std::string>& headers) :
               m_verb(verb),
               m_location(location),
               m_headers(headers)
               {}

         private:
            std::string m_verb;
            std::string m_location;
            std::map<std::string, std::string> m_headers;
         };

      class Callbacks
         {
         public:
            virtual void handle_http_request(const Request& request) = 0;
            virtual ~Callbacks() = default;
         };

      HTTP_Parser(Callbacks& cb) : m_cb(cb) {}

      void consume_input(const uint8_t buf[], size_t buf_len)
         {
         m_req_buf.append(reinterpret_cast<const char*>(buf), buf_len);

         std::istringstream strm(m_req_buf);

         std::string http_version;
         std::string verb;
         std::string location;
         std::map<std::string, std::string> headers;

         strm >> verb >> location >> http_version;

         if(verb.empty() || location.empty())
            return;

         while(true)
            {
            std::string header_line;
            std::getline(strm, header_line);

            if(header_line == "\r")
               {
               continue;
               }

            auto delim = header_line.find(": ");
            if(delim == std::string::npos)
               {
               break;
               }

            const std::string hdr_name = header_line.substr(0, delim);
            const std::string hdr_val = header_line.substr(delim + 2, std::string::npos);

            headers[hdr_name] = hdr_val;

            if(headers.size() > 1024)
               throw Botan::Invalid_Argument("Too many HTTP headers sent in request");
            }

         if(verb != "" && location != "")
            {
            Request req(verb, location, headers);
            m_cb.handle_http_request(req);
            m_req_buf.clear();
            }
         else
            printf("ignoring\n");
         }
   private:
      Callbacks& m_cb;
      std::string m_req_buf;
   };

static const size_t READBUF_SIZE = 4096;

class TLS_Asio_HTTP_Session final : public boost::enable_shared_from_this<TLS_Asio_HTTP_Session>,
                                    public Botan::TLS::Callbacks,
                                    public HTTP_Parser::Callbacks
   {
   public:
      typedef boost::shared_ptr<TLS_Asio_HTTP_Session> pointer;

      static pointer create(
         boost::asio::io_service& io,
         Botan::TLS::Session_Manager& session_manager,
         Botan::Credentials_Manager& credentials,
         Botan::TLS::Policy& policy)
         {
         return pointer(new TLS_Asio_HTTP_Session(io, session_manager, credentials, policy));
         }

      tcp::socket& client_socket()
         {
         return m_client_socket;
         }

      void start()
         {
         m_c2s.resize(READBUF_SIZE);
         client_read(boost::system::error_code(), 0); // start read loop
         }

      void stop()
         {
         m_tls.close();
         }

   private:
      TLS_Asio_HTTP_Session(boost::asio::io_service& io,
                            Botan::TLS::Session_Manager& session_manager,
                            Botan::Credentials_Manager& credentials,
                            Botan::TLS::Policy& policy)
         : m_strand(io)
         , m_client_socket(io)
         , m_tls(*this, session_manager, credentials, policy, m_rng) {}

      void client_read(const boost::system::error_code& error,
                       size_t bytes_transferred)
         {
         if(error)
            {
            stop();
            return;
            }

         try
            {
            m_tls.received_data(&m_c2s[0], bytes_transferred);
            }
         catch(Botan::Exception& e)
            {
            log_exception("TLS connection failed", e);
            stop();
            return;
            }

         m_client_socket.async_read_some(
            boost::asio::buffer(&m_c2s[0], m_c2s.size()),
            m_strand.wrap(
               boost::bind(
                  &TLS_Asio_HTTP_Session::client_read, shared_from_this(),
                  boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred)));
         }

      void handle_client_write_completion(const boost::system::error_code& error)
         {
         if(error)
            {
            stop();
            return;
            }

         m_s2c.clear();

         if(m_s2c_pending.empty() && m_tls.is_closed())
            {
            m_client_socket.close();
            }
         tls_emit_data(nullptr, 0); // initiate another write if needed
         }

      std::string tls_server_choose_app_protocol(const std::vector<std::string>& client_protos) override
         {
         return "http/1.1";
         }

      void tls_record_received(uint64_t /*rec_no*/, const uint8_t buf[], size_t buf_len) override
         {
         if(!m_http_parser)
            m_http_parser.reset(new HTTP_Parser(*this));

         m_http_parser->consume_input(buf, buf_len);
         }

      std::string summarize_request(const HTTP_Parser::Request& request)
         {
         std::ostringstream strm;

         strm << "Client " << client_socket().remote_endpoint().address().to_string()
              << " requested " << request.verb() << " " << request.location() << "\n";

         if(request.headers().empty() == false)
            {
            strm << "Client HTTP headers:\n";
            for(auto kv : request.headers())
               strm << " " << kv.first << ": " << kv.second << "\n";
            }

         return strm.str();
         }

      void handle_http_request(const HTTP_Parser::Request& request) override
         {
         std::ostringstream response;
         if(request.verb() != "GET")
            {
            response << "HTTP/1.0 405 Method Not Allowed\r\n\r\nNo POST for you";
            }
         else
            {
            if(request.location() == "/" || request.location() == "/status")
               {
               const std::string http_summary = summarize_request(request);

               const std::string report = http_summary + m_session_summary + m_chello_summary;

               response << "HTTP/1.0 200 OK\r\n";
               response << "Server: " << Botan::version_string() << "\r\n";
               response << "Content-Type: text/plain\r\n";
               response << "Content-Length: " << report.size() << "\r\n";
               response << "\r\n";

               response << report;
               }
            else
               {
               response << "HTTP/1.0 404 Not Found\r\n\r\nSorry, no";
               }
            }

         const std::string response_str = response.str();
         m_tls.send(response_str);
         m_tls.close();
         }

      void tls_emit_data(const uint8_t buf[], size_t buf_len) override
         {
         if(buf_len > 0)
            {
            m_s2c_pending.insert(m_s2c_pending.end(), buf, buf + buf_len);
            }

         // no write now active and we still have output pending
         if(m_s2c.empty() && !m_s2c_pending.empty())
            {
            std::swap(m_s2c_pending, m_s2c);

            boost::asio::async_write(
               m_client_socket,
               boost::asio::buffer(&m_s2c[0], m_s2c.size()),
               m_strand.wrap(
                  boost::bind(
                     &TLS_Asio_HTTP_Session::handle_client_write_completion,
                     shared_from_this(),
                     boost::asio::placeholders::error)));
            }
         }

      bool tls_session_established(const Botan::TLS::Session& session) override
         {
         std::ostringstream strm;

         strm << "TLS negotiation with " << Botan::version_string() << " test server\n\n";

         strm << "Version: " << session.version().to_string() << "\n";
         strm << "Ciphersuite: " << session.ciphersuite().to_string() << "\n";
         if(session.session_id().empty() == false)
            {
            strm << "SessionID: " << Botan::hex_encode(session.session_id()) << "\n";
            }
         if(session.server_info().hostname() != "")
            {
            strm << "SNI: " << session.server_info().hostname() << "\n";
            }

         m_session_summary = strm.str();
         return true;
         }

      void tls_inspect_handshake_msg(const Botan::TLS::Handshake_Message& message)
         {
         if(message.type() == Botan::TLS::CLIENT_HELLO)
            {
            const Botan::TLS::Client_Hello& client_hello = dynamic_cast<const Botan::TLS::Client_Hello&>(message);

            std::ostringstream strm;

            strm << "Client random: " << Botan::hex_encode(client_hello.random()) << "\n";

            strm << "Client offered following ciphersuites:\n";
            for(uint16_t suite_id : client_hello.ciphersuites())
               {
               Botan::TLS::Ciphersuite ciphersuite = Botan::TLS::Ciphersuite::by_id(suite_id);

               strm << " - 0x"
                    << std::hex << std::setfill('0') << std::setw(4) << suite_id
                    << std::dec << std::setfill(' ') << std::setw(0) << " ";

               if(ciphersuite.valid())
                  strm << ciphersuite.to_string() << "\n";
               else if(suite_id == 0x00FF)
                  strm << "Renegotiation SCSV\n";
               else
                  strm << "Unknown ciphersuite\n";
               }

            m_chello_summary = strm.str();
            }

         }

      void tls_alert(Botan::TLS::Alert alert) override
         {
         if(alert.type() == Botan::TLS::Alert::CLOSE_NOTIFY)
            {
            m_tls.close();
            return;
            }
         else
            {
            std::cout << "Alert " << alert.type_string() << std::endl;
            }
         }

      boost::asio::io_service::strand m_strand;

      tcp::socket m_client_socket;

#if defined(BOTAN_HAS_SYSTEM_RNG)
      Botan::System_RNG m_rng;
#else
      Botan::AutoSeeded_RNG m_rng;
#endif
      Botan::TLS::Server m_tls;
      std::string m_chello_summary;
      std::string m_session_summary;
      std::unique_ptr<HTTP_Parser> m_http_parser;

      std::vector<uint8_t> m_c2s;
      std::vector<uint8_t> m_s2c;
      std::vector<uint8_t> m_s2c_pending;
   };

class TLS_Asio_HTTP_Server final
   {
   public:
      typedef TLS_Asio_HTTP_Session session;

      TLS_Asio_HTTP_Server(
         boost::asio::io_service& io, unsigned short port,
         Botan::Credentials_Manager& creds,
         Botan::TLS::Policy& policy,
         Botan::TLS::Session_Manager& session_mgr)
         : m_acceptor(io, tcp::endpoint(tcp::v4(), port))
         , m_creds(creds)
         , m_policy(policy)
         , m_session_manager(session_mgr)
         {
         session::pointer new_session = make_session();

         m_acceptor.async_accept(
            new_session->client_socket(),
            boost::bind(
               &TLS_Asio_HTTP_Server::handle_accept,
               this,
               new_session,
               boost::asio::placeholders::error));
         }

   private:
      session::pointer make_session()
         {
         return session::create(
                   m_acceptor.get_io_service(),
                   m_session_manager,
                   m_creds,
                   m_policy);
         }

      void handle_accept(session::pointer new_session,
                         const boost::system::error_code& error)
         {
         if(!error)
            {
            new_session->start();
            new_session = make_session();

            m_acceptor.async_accept(
               new_session->client_socket(),
               boost::bind(
                  &TLS_Asio_HTTP_Server::handle_accept,
                  this,
                  new_session,
                  boost::asio::placeholders::error));
            }
         }

      tcp::acceptor m_acceptor;

      Botan::Credentials_Manager& m_creds;
      Botan::TLS::Policy& m_policy;
      Botan::TLS::Session_Manager& m_session_manager;
   };

}

class TLS_HTTP_Server final : public Command
   {
   public:
      TLS_HTTP_Server() : Command("tls_http_server server_cert server_key "
                                  "--port=443 --policy= --threads=0 "
                                  "--session-db= --session-db-pass=") {}

      std::string group() const override
         {
         return "tls";
         }

      std::string description() const override
         {
         return "Provides a simple HTTP server";
         }

      size_t thread_count() const
         {
         if(size_t t = get_arg_sz("threads"))
            return t;
         if(size_t t = std::thread::hardware_concurrency())
            return t;
         return 2;
         }

      void go() override
         {
         const size_t listen_port = get_arg_sz("port");

         const std::string server_crt = get_arg("server_cert");
         const std::string server_key = get_arg("server_key");

         const size_t num_threads = thread_count();

         Basic_Credentials_Manager creds(rng(), server_crt, server_key);

         std::unique_ptr<Botan::TLS::Policy> policy;

         const std::string policy_file = get_arg("policy");
         if(policy_file.size() > 0)
            {
            std::ifstream policy_stream(policy_file);
            if(!policy_stream.good())
               {
               error_output() << "Failed reading policy file\n";
               return;
               }
            policy.reset(new Botan::TLS::Text_Policy(policy_stream));
            }

         if(!policy)
            {
            policy.reset(new Botan::TLS::Policy);
            }

         std::unique_ptr<Botan::TLS::Session_Manager> session_mgr;

         const std::string sessions_db = get_arg("session-db");

         if(!sessions_db.empty())
            {
#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
            const std::string sessions_passphrase = get_passphrase_arg("Session DB passphrase", "session-db-pass");
            session_mgr.reset(new Botan::TLS::Session_Manager_SQLite(sessions_passphrase, rng(), sessions_db));
#else
            throw CLI_Error_Unsupported("Sqlite3 support not available");
#endif
            }

         if(!session_mgr)
            {
            session_mgr.reset(new Botan::TLS::Session_Manager_In_Memory(rng()));
            }

         boost::asio::io_service io;

         TLS_Asio_HTTP_Server server(io, listen_port, creds, *policy, *session_mgr);

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

BOTAN_REGISTER_COMMAND("tls_http_server", TLS_HTTP_Server);

}

#endif
