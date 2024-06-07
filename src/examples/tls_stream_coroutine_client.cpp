
#include <iostream>

#include <botan/asio_compat.h>

// Boost 1.81.0 introduced support for the finalized C++20 coroutines
// in clang 14 and newer. Older versions of Boost might work with other
// compilers, though.
#if defined(BOTAN_FOUND_COMPATIBLE_BOOST_ASIO_VERSION) && BOOST_VERSION >= 108100

   #include <botan/asio_stream.h>
   #include <botan/auto_rng.h>
   #include <botan/certstor_system.h>
   #include <botan/credentials_manager.h>
   #include <botan/tls_session_manager_memory.h>
   #include <botan/version.h>

   #include <boost/asio/awaitable.hpp>
   #include <boost/asio/co_spawn.hpp>
   #include <boost/asio/detached.hpp>
   #include <boost/asio/use_awaitable.hpp>
   #include <boost/beast/core.hpp>
   #include <boost/beast/http.hpp>
   #include <boost/beast/version.hpp>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace tls = Botan::TLS;
using tcp = boost::asio::ip::tcp;

namespace {

/**
 * A simple credentials manager that uses the system's trust store
 * to verify certificates.
 */
class System_Credentials_Manager : public Botan::Credentials_Manager {
   public:
      std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(const std::string&,
                                                                             const std::string&) override {
         return {&m_cert_store};
      }

   private:
      Botan::System_Certificate_Store m_cert_store;
};

/**
 * Helper function to set up a Botan TLS Context for the ASIO wrapper.
 */
std::shared_ptr<tls::Context> prepare_context_for(std::string_view server_info) {
   auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
   return std::make_shared<tls::Context>(std::make_shared<System_Credentials_Manager>(),
                                         rng,
                                         std::make_shared<tls::Session_Manager_In_Memory>(rng),
                                         std::make_shared<tls::Policy>(),
                                         tls::Server_Information(server_info));
}

http::request<http::string_body> create_GET_request(const std::string& host, const std::string& target) {
   http::request<http::string_body> req;
   req.version(11);
   req.method(http::verb::get);
   req.target(target);
   req.set(http::field::host, host);
   req.set(http::field::user_agent, Botan::version_string());
   return req;
}

net::awaitable<void> request(std::string host, std::string port, std::string target) {
   // Lookup host address
   auto resolver = net::use_awaitable.as_default_on(tcp::resolver(co_await net::this_coro::executor));
   const auto dns_result = co_await resolver.async_resolve(host, port);

   // Connect to host and establish a TLS session
   auto tls_stream =
      tls::Stream(prepare_context_for(host),
                  net::use_awaitable.as_default_on(beast::tcp_stream(co_await net::this_coro::executor)));
   tls_stream.next_layer().expires_after(std::chrono::seconds(30));
   co_await tls_stream.next_layer().async_connect(dns_result);
   co_await tls_stream.async_handshake(tls::Connection_Side::Client);

   // Send HTTP GET request
   tls_stream.next_layer().expires_after(std::chrono::seconds(30));
   co_await http::async_write(tls_stream, create_GET_request(host, target));

   // Receive HTTP response and print result
   beast::flat_buffer b;
   http::response<http::dynamic_body> res;
   co_await http::async_read(tls_stream, b, res);
   std::cout << res << std::endl;

   // Terminate connection
   co_await tls_stream.async_shutdown();
   tls_stream.next_layer().close();
}

}  // namespace

int main(int argc, char* argv[]) {
   if(argc != 4) {
      std::cerr << "Usage: tls_stream_coroutine_client <host> <port> <target>\n"
                << "Example:\n"
                << "    tls_stream_coroutine_client botan.randombit.net 443 /news.html\n";
      return 1;
   }

   const auto host = argv[1];
   const auto port = argv[2];
   const auto target = argv[3];

   int return_code = 0;

   try {
      net::io_context ioc;

      net::co_spawn(ioc, request(host, port, target), [&](const std::exception_ptr& eptr) {
         if(eptr) {
            try {
               std::rethrow_exception(eptr);
            } catch(std::exception& ex) {
               std::cerr << "Error: " << ex.what() << "\n";
               return_code = 1;
            }
         }
      });

      ioc.run();
   } catch(std::exception& e) {
      std::cerr << e.what() << "\n";
   }

   return return_code;
}

#else

int main() {
   std::cout << "Your boost version is too old, sorry.\n"
             << "Or did you compile Botan without --with-boost?\n";
   return 1;
}

#endif
