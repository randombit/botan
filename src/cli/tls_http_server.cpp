/*
* (C) 2014,2015,2017,2019,2023 Jack Lloyd
* (C) 2016 Matthias Gierlings
* (C) 2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* This implementation is roughly based on this BSL-licensed example
* by Klemens D. Morgenstern:
*   www.boost.org/doc/libs/1_83_0/libs/beast/example/http/server/awaitable/http_server_awaitable.cpp
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_TLS_ASIO_STREAM)
   #include <botan/asio_compat.h>
#endif

#if defined(BOTAN_FOUND_COMPATIBLE_BOOST_ASIO_VERSION)
   #include <boost/asio/awaitable.hpp>
#endif

// If your boost version is too old, this might not be defined despite
// your toolchain supporting C++20 co_await.
#if defined(BOOST_ASIO_HAS_CO_AWAIT) && defined(BOTAN_HAS_TLS) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

   #include <ctime>
   #include <iomanip>
   #include <memory>
   #include <string>
   #include <thread>
   #include <vector>

   #include <boost/asio/co_spawn.hpp>
   #include <boost/asio/ip/tcp.hpp>
   #include <boost/asio/use_awaitable.hpp>
   #include <boost/beast/http.hpp>

   #include <botan/asio_stream.h>
   #include <botan/tls_messages.h>
   #include <botan/tls_session_manager_memory.h>
   #include <botan/version.h>
   #include <botan/internal/fmt.h>

   #if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
      #include <botan/tls_session_manager_sqlite.h>
   #endif

   #if defined(BOTAN_HAS_OS_UTILS)
      #include <botan/internal/os_utils.h>
   #endif

   #include "tls_helpers.h"

namespace Botan_CLI {

namespace {

namespace beast = boost::beast;    // from <boost/beast.hpp>
namespace http = beast::http;      // from <boost/beast/http.hpp>
namespace net = boost::asio;       // from <boost/asio.hpp>
using tcp = boost::asio::ip::tcp;  // from <boost/asio/ip/tcp.hpp>

using tcp_stream = typename beast::tcp_stream::rebind_executor<
   net::use_awaitable_t<>::executor_with_default<net::any_io_executor>>::other;

class Logger final {
   private:
      std::string timestamp() const {
   #if defined(BOTAN_HAS_OS_UTILS)
         return Botan::OS::format_time(std::time(nullptr), "%c");
   #else
         return std::to_string(std::time(nullptr));
   #endif
      }

   public:
      Logger(std::ostream& out, std::ostream& err) : m_out(out), m_err(err) {}

      void log(std::string_view out) {
         std::scoped_lock lk(m_mutex);
         m_out << Botan::fmt("[{}] {}", timestamp(), out) << "\n";
      }

      void error(std::string_view err) {
         std::scoped_lock lk(m_mutex);
         m_err << Botan::fmt("[{}] {}", timestamp(), err) << "\n";
      }

      void flush() {
         std::scoped_lock lk(m_mutex);
         m_out.flush();
         m_err.flush();
      }

   private:
      std::mutex m_mutex;
      std::ostream& m_out;
      std::ostream& m_err;
};

class TlsHttpCallbacks final : public Botan::TLS::StreamCallbacks {
   public:
      void tls_session_activated() override {
         std::ostringstream strm;

         strm << "TLS negotiation with " << Botan::version_string() << " test server\n\n";

         m_connection_summary = strm.str();
      }

      void tls_session_established(const Botan::TLS::Session_Summary& session) override {
         std::ostringstream strm;

         strm << "Version: " << session.version().to_string() << "\n";
         strm << "Ciphersuite: " << session.ciphersuite().to_string() << "\n";
         if(const auto& session_id = session.session_id(); !session_id.empty()) {
            strm << "SessionID: " << Botan::hex_encode(session_id.get()) << "\n";
         }
         if(!session.server_info().hostname().empty()) {
            strm << "SNI: " << session.server_info().hostname() << "\n";
         }

         m_session_summary = strm.str();
      }

      void tls_inspect_handshake_msg(const Botan::TLS::Handshake_Message& message) override {
         if(message.type() == Botan::TLS::Handshake_Type::ClientHello) {
            const Botan::TLS::Client_Hello& client_hello = dynamic_cast<const Botan::TLS::Client_Hello&>(message);

            std::ostringstream strm;

            strm << "Client random: " << Botan::hex_encode(client_hello.random()) << "\n";

            strm << "Client offered following ciphersuites:\n";
            for(uint16_t suite_id : client_hello.ciphersuites()) {
               const auto ciphersuite = Botan::TLS::Ciphersuite::by_id(suite_id);

               strm << " - 0x" << std::hex << std::setfill('0') << std::setw(4) << suite_id << std::dec
                    << std::setfill(' ') << std::setw(0) << " ";

               if(ciphersuite && ciphersuite->valid()) {
                  strm << ciphersuite->to_string() << "\n";
               } else if(suite_id == 0x00FF) {
                  strm << "Renegotiation SCSV\n";
               } else {
                  strm << "Unknown ciphersuite\n";
               }
            }

            m_chello_summary = strm.str();
         }
      }

      std::string summary() const {
         BOTAN_STATE_CHECK(!m_connection_summary.empty() && !m_session_summary.empty() && !m_chello_summary.empty());
         return m_connection_summary + m_session_summary + m_chello_summary;
      }

   private:
      std::string m_chello_summary;
      std::string m_connection_summary;
      std::string m_session_summary;
};

std::string summarize_request(const Botan::TLS::Stream<tcp_stream>& tls_stream,
                              const http::request<http::string_body>& req) {
   std::ostringstream strm;

   const auto& remote = tls_stream.next_layer().socket().remote_endpoint();

   strm << "Client " << remote.address().to_string() << " requested " << req.method_string() << " " << req.target()
        << "\n";

   if(std::distance(req.begin(), req.end()) > 0) {
      strm << "Client HTTP headers:\n";
      for(const auto& header : req) {
         strm << " " << header.name_string() << ": " << header.value() << "\n";
      }
   }

   return strm.str();
}

auto make_final_completion_handler(const std::shared_ptr<Logger>& logger, const std::string& context) {
   return [=](std::exception_ptr e) {
      if(e) {
         try {
            std::rethrow_exception(std::move(e));
         } catch(const std::exception& ex) {
            logger->error(Botan::fmt("{}: {}", context, ex.what()));
         }
      }
   };
}

std::shared_ptr<http::response<http::string_body>> handle_response(const http::request<http::string_body>& req,
                                                                   const std::shared_ptr<TlsHttpCallbacks>& callbacks,
                                                                   const Botan::TLS::Stream<tcp_stream>& tls_stream,
                                                                   const std::shared_ptr<Logger>& logger) {
   logger->log(Botan::fmt("{} {}", req.method_string(), req.target()));

   auto [status_code, msg] = [&]() -> std::tuple<http::status, std::string> {
      if(req.method() != http::verb::get) {
         return {http::status::method_not_allowed, "Unsupported HTTP verb\n"};
      } else if(req.target() == "/" || req.target() == "/status") {
         return {http::status::ok, callbacks->summary() + summarize_request(tls_stream, req)};
      } else {
         return {http::status::not_found, "Not found\n"};
      }
   }();

   auto response = std::make_shared<http::response<http::string_body>>(status_code, req.version());
   response->body() = msg;
   response->set(http::field::content_type, "text/plain");
   response->keep_alive(req.keep_alive());
   response->prepare_payload();

   return response;
}

net::awaitable<void> do_session(tcp_stream stream,
                                std::shared_ptr<Botan::TLS::Context> tls_ctx,
                                std::shared_ptr<Logger> logger) {
   // This buffer is required to persist across reads
   beast::flat_buffer buffer;

   // Set up Botan's TLS stack
   auto callbacks = std::make_shared<TlsHttpCallbacks>();
   Botan::TLS::Stream<tcp_stream> tls_stream(std::move(stream), std::move(tls_ctx), callbacks);

   std::exception_ptr protocol_exception;

   try {
      // Perform a TLS handshake with the peer
      co_await tls_stream.async_handshake(Botan::TLS::Connection_Side::Server);

      while(true) {
         // Set the timeout.
         tls_stream.next_layer().expires_after(std::chrono::seconds(30));

         // Read a request
         http::request<http::string_body> req;
         co_await http::async_read(tls_stream, buffer, req);

         // Handle the request
         auto response = handle_response(req, callbacks, tls_stream, logger);

         // Send the response
         co_await http::async_write(tls_stream, *response);

         // Determine if we should close the connection
         if(!response->keep_alive()) {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            break;
         }
      }
   } catch(boost::system::system_error& se) {
      if(se.code() != http::error::end_of_stream) {
         // Something went wrong during the communication, as good citizens we
         // try to shutdown the connection gracefully, anyway. The protocol
         // exception is kept for later re-throw.
         protocol_exception = std::current_exception();
      }
   }

   try {
      // Shut down the connection gracefully. It gives the stream a chance to
      // flush remaining send buffers and/or close the connection gracefully. If
      // the communication above failed this may or may not be successful.
      co_await tls_stream.async_shutdown();
      tls_stream.next_layer().close();
   } catch(const std::exception&) {
      // if the protocol interaction above produced an exception the shutdown
      // was "best effort" anyway and we swallow the secondary exception that
      // happened during shutdown.
      if(!protocol_exception) {
         throw;
      }
   }

   if(protocol_exception) {
      std::rethrow_exception(protocol_exception);
   }

   // At this point the connection is closed gracefully
   // we ignore the error because the client might have
   // dropped the connection already.
}

net::awaitable<void> do_listen(tcp::endpoint endpoint,
                               std::shared_ptr<Botan::TLS::Context> tls_ctx,
                               size_t max_clients,
                               std::shared_ptr<Logger> logger) {
   auto acceptor = net::use_awaitable.as_default_on(tcp::acceptor(co_await net::this_coro::executor));
   acceptor.open(endpoint.protocol());
   acceptor.set_option(net::socket_base::reuse_address(true));
   acceptor.bind(endpoint);
   acceptor.listen(net::socket_base::max_listen_connections);

   // If max_clients is zero in the beginning, we'll serve forever
   // otherwise we'll count down and stop eventually.

   const bool run_forever = (max_clients == 0);

   logger->log(Botan::fmt("Listening for new connections on {}:{}", endpoint.address().to_string(), endpoint.port()));
   logger->flush();

   auto done = [&] {
      if(run_forever) {
         return false;
      } else {
         return max_clients-- == 0;
      }
   };

   while(!done()) {
      boost::asio::co_spawn(acceptor.get_executor(),
                            do_session(tcp_stream(co_await acceptor.async_accept()), tls_ctx, logger),
                            make_final_completion_handler(logger, "Session"));
   }
}

}  // namespace

class TLS_HTTP_Server final : public Command {
   public:
      TLS_HTTP_Server() :
            Command(
               "tls_http_server server_cert server_key "
               "--port=443 --policy=default --threads=0 --max-clients=0 "
               "--session-db= --session-db-pass=") {}

      std::string group() const override { return "tls"; }

      std::string description() const override { return "Provides a simple HTTP server"; }

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
         const uint16_t listen_port = get_arg_u16("port");

         const std::string server_crt = get_arg("server_cert");
         const std::string server_key = get_arg("server_key");

         const size_t num_threads = thread_count();
         const size_t max_clients = get_arg_sz("max-clients");

         auto creds = std::make_shared<Basic_Credentials_Manager>(server_crt, server_key);

         auto policy = load_tls_policy(get_arg("policy"));

         std::shared_ptr<Botan::TLS::Session_Manager> session_mgr;

         const std::string sessions_db = get_arg("session-db");

         if(!sessions_db.empty()) {
   #if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
            const std::string sessions_passphrase = get_passphrase_arg("Session DB passphrase", "session-db-pass");
            session_mgr =
               std::make_shared<Botan::TLS::Session_Manager_SQLite>(sessions_passphrase, rng_as_shared(), sessions_db);
   #else
            throw CLI_Error_Unsupported("Sqlite3 support not available");
   #endif
         }

         if(!session_mgr) {
            session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng_as_shared());
         }

         auto logger = std::make_shared<Logger>(output(), error_output());

         net::io_context io{static_cast<int>(num_threads)};
         auto address = net::ip::make_address("0.0.0.0");
         boost::asio::co_spawn(
            io,
            do_listen(tcp::endpoint{address, listen_port},
                      std::make_shared<Botan::TLS::Context>(creds, rng_as_shared(), session_mgr, policy),
                      max_clients,
                      logger),
            make_final_completion_handler(logger, "Acceptor"));

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

BOTAN_REGISTER_COMMAND("tls_http_server", TLS_HTTP_Server);

}  // namespace Botan_CLI

#endif
