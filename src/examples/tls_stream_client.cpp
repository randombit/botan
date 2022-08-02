#include <iostream>

#include <botan/asio_stream.h>
#include <botan/auto_rng.h>
#include <botan/certstor_system.h>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/bind.hpp>

namespace http = boost::beast::http;
namespace _ = boost::asio::placeholders;

// very basic credentials manager
class Credentials_Manager : public Botan::Credentials_Manager
   {
   public:
      Credentials_Manager() {}

      std::vector<Botan::Certificate_Store*>
      trusted_certificate_authorities(const std::string&, const std::string&) override
         {
         return {&cert_store_};
         }

   private:
      Botan::System_Certificate_Store cert_store_;
   };

// a simple https client based on TLS::Stream
class client
   {
   public:
      client(boost::asio::io_context&                 io_context,
               boost::asio::ip::tcp::resolver::iterator endpoint_iterator,
               http::request<http::string_body>         req)
         : request_(req)
         , ctx_(credentials_mgr_,
                  rng_,
                  session_mgr_,
                  policy_,
                  Botan::TLS::Server_Information())
         , stream_(io_context, ctx_)
         {
         boost::asio::async_connect(stream_.lowest_layer(), endpoint_iterator,
                                    boost::bind(&client::handle_connect, this, _::error));
         }

      void handle_connect(const boost::system::error_code& error)
         {
         if(error)
            {
            std::cout << "Connect failed: " << error.message() << "\n";
            return;
            }
         stream_.async_handshake(Botan::TLS::Connection_Side::CLIENT,
                                 boost::bind(&client::handle_handshake, this, _::error));
         }

      void handle_handshake(const boost::system::error_code& error)
         {
         if(error)
            {
            std::cout << "Handshake failed: " << error.message() << "\n";
            return;
            }
         http::async_write(stream_, request_,
                           boost::bind(&client::handle_write, this, _::error, _::bytes_transferred));
         }

      void handle_write(const boost::system::error_code& error, size_t)
         {
         if(error)
            {
            std::cout << "Write failed: " << error.message() << "\n";
            return;
            }
         http::async_read(stream_, reply_, response_,
                           boost::bind(&client::handle_read, this, _::error, _::bytes_transferred));
         }

      void handle_read(const boost::system::error_code& error, size_t)
         {
         if(!error)
            {
            std::cout << "Reply: ";
            std::cout << response_.body() << "\n";
            }
         else
            {
            std::cout << "Read failed: " << error.message() << "\n";
            }
         }

   private:
      http::request<http::dynamic_body> request_;
      http::response<http::string_body> response_;
      boost::beast::flat_buffer         reply_;

      Botan::TLS::Session_Manager_Noop session_mgr_;
      Botan::AutoSeeded_RNG            rng_;
      Credentials_Manager              credentials_mgr_;
      Botan::TLS::Policy               policy_;

      Botan::TLS::Context                              ctx_;
      Botan::TLS::Stream<boost::asio::ip::tcp::socket> stream_;
   };

int main()
   {
   boost::asio::io_context io_context;

   boost::asio::ip::tcp::resolver           resolver(io_context);
   boost::asio::ip::tcp::resolver::query    query("botan.randombit.net", "443");
   boost::asio::ip::tcp::resolver::iterator iterator = resolver.resolve(query);

   http::request<http::string_body> req;
   req.version(11);
   req.method(http::verb::get);
   req.target("/news.html");
   req.set(http::field::host, "botan.randombit.net");

   client c(io_context, iterator, req);

   io_context.run();
   }
