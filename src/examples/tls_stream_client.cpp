#include <iostream>

#include <botan/asio_compat.h>
#if defined(BOTAN_FOUND_COMPATIBLE_BOOST_ASIO_VERSION)

   #include <botan/asio_stream.h>
   #include <botan/auto_rng.h>
   #include <botan/certstor_system.h>
   #include <botan/tls.h>
   #include <botan/version.h>

   #include <boost/asio.hpp>
   #include <boost/beast.hpp>
   #include <boost/bind.hpp>
   #include <utility>

namespace http = boost::beast::http;
namespace ap = boost::asio::placeholders;

// very basic credentials manager
class Credentials_Manager : public Botan::Credentials_Manager {
   public:
      Credentials_Manager() = default;

      std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(const std::string&,
                                                                             const std::string&) override {
         return {&m_cert_store};
      }

   private:
      Botan::System_Certificate_Store m_cert_store;
};

// a simple https client based on TLS::Stream
class client {
   public:
      client(boost::asio::io_context& io_context,
             const boost::asio::ip::tcp::resolver::results_type& endpoints,
             std::string_view host,
             const http::request<http::string_body>& req) :
            m_request(req),
            m_ctx(std::make_shared<Botan::TLS::Context>(std::make_shared<Credentials_Manager>(),
                                                        std::make_shared<Botan::AutoSeeded_RNG>(),
                                                        std::make_shared<Botan::TLS::Session_Manager_Noop>(),
                                                        std::make_shared<Botan::TLS::Policy>(),
                                                        host)),
            m_stream(io_context, m_ctx) {
         boost::asio::async_connect(m_stream.lowest_layer(),
                                    endpoints.begin(),
                                    endpoints.end(),
                                    boost::bind(&client::handle_connect, this, ap::error));
      }

      void handle_connect(const boost::system::error_code& error) {
         if(error) {
            std::cout << "Connect failed: " << error.message() << '\n';
            return;
         }
         m_stream.async_handshake(Botan::TLS::Connection_Side::Client,
                                  boost::bind(&client::handle_handshake, this, ap::error));
      }

      void handle_handshake(const boost::system::error_code& error) {
         if(error) {
            std::cout << "Handshake failed: " << error.message() << '\n';
            return;
         }
         http::async_write(
            m_stream, m_request, boost::bind(&client::handle_write, this, ap::error, ap::bytes_transferred));
      }

      void handle_write(const boost::system::error_code& error, size_t) {
         if(error) {
            std::cout << "Write failed: " << error.message() << '\n';
            return;
         }
         http::async_read(
            m_stream, m_reply, m_response, boost::bind(&client::handle_read, this, ap::error, ap::bytes_transferred));
      }

      void handle_read(const boost::system::error_code& error, size_t) {
         if(!error) {
            std::cout << "Reply: ";
            std::cout << m_response.body() << '\n';
         } else {
            std::cout << "Read failed: " << error.message() << '\n';
         }
      }

   private:
      http::request<http::dynamic_body> m_request;
      http::response<http::string_body> m_response;
      boost::beast::flat_buffer m_reply;

      std::shared_ptr<Botan::TLS::Context> m_ctx;
      Botan::TLS::Stream<boost::asio::ip::tcp::socket> m_stream;
};

int main(int argc, char* argv[]) {
   if(argc != 4) {
      std::cerr << "Usage: tls_stream_client <host> <port> <target>\n"
                << "Example:\n"
                << "    tls_stream_client botan.randombit.net 443 /news.html\n";
      return 1;
   }

   const auto host = argv[1];
   const auto port = argv[2];
   const auto target = argv[3];

   try {
      boost::asio::io_context io_context;

      boost::asio::ip::tcp::resolver resolver(io_context);
      boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(host, port);

      http::request<http::string_body> req;
      req.version(11);
      req.method(http::verb::get);
      req.target(target);
      req.set(http::field::host, host);
      req.set(http::field::user_agent, Botan::version_string());

      client c(io_context, endpoints, host, req);

      io_context.run();
   } catch(std::exception& e) {
      std::cerr << e.what();
      return 1;
   }

   return 0;
}

#else

int main() {
   std::cout << "Your boost version is too old, sorry.\n"
             << "Or did you compile Botan without --with-boost?\n";
   return 1;
}

#endif
