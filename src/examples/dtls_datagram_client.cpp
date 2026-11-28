/*
* DTLS Asio coroutine client example
* (C) 2026 The Botan Authors
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asio_compat.h>

#include <iostream>

#if defined(BOTAN_FOUND_COMPATIBLE_BOOST_ASIO_DATAGRAM_VERSION) && BOOST_VERSION >= 108100 && \
   defined(BOTAN_HAS_AUTO_SEEDING_RNG) && defined(BOTAN_HAS_TLS_12)

   #include <botan/asio_datagram.h>
   #include <botan/auto_rng.h>
   #include <botan/certstor.h>
   #include <botan/tls_session_manager_noop.h>
   #include <botan/x509cert.h>

   #include <boost/asio/any_io_executor.hpp>
   #include <boost/asio/awaitable.hpp>
   #include <boost/asio/bind_cancellation_slot.hpp>
   #include <boost/asio/buffer.hpp>
   #include <boost/asio/cancellation_signal.hpp>
   #include <boost/asio/co_spawn.hpp>
   #include <boost/asio/io_context.hpp>
   #include <boost/asio/ip/udp.hpp>
   #include <boost/asio/steady_timer.hpp>
   #include <boost/asio/strand.hpp>
   #include <boost/asio/use_awaitable.hpp>

   #include <array>
   #include <chrono>
   #include <exception>
   #include <memory>
   #include <stdexcept>
   #include <string>
   #include <string_view>
   #include <utility>
   #include <vector>

namespace net = boost::asio;
namespace tls = Botan::TLS;
using udp = net::ip::udp;

namespace {

class Client_Credentials final : public Botan::Credentials_Manager {
   public:
      explicit Client_Credentials(std::string_view ca_file) : m_trusted_ca(Botan::X509_Certificate(ca_file)) {}

      std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(const std::string& /*type*/,
                                                                             const std::string& /*context*/) override {
         return {&m_trusted_ca};
      }

   private:
      Botan::Certificate_Store_In_Memory m_trusted_ca;
};

class Example_Policy final : public tls::Policy {
   public:
      // Local echo servers typically do not provide certificate revocation information.
      bool require_cert_revocation_info() const override { return false; }
};

constexpr auto echo = [](net::any_io_executor executor,
                         std::string host,
                         std::string port,
                         std::string ca_file,
                         std::string message) -> net::awaitable<void> {
   // Keep the request within one DTLS record at the default MTU.
   if(message.size() >= 1024) {
      throw std::invalid_argument("Message must be shorter than 1024 bytes");
   }
   message += '\n';  // Botan's CLI echo server replies to complete lines.

   udp::resolver resolver(executor);
   const auto endpoints = co_await resolver.async_resolve(host, port, net::use_awaitable);
   const auto peer = endpoints.begin()->endpoint();
   udp::socket socket(executor, peer.protocol());
   socket.connect(peer);

   auto context = std::make_shared<tls::Context>(std::make_shared<Client_Credentials>(ca_file),
                                                 std::make_shared<Botan::AutoSeeded_RNG>(),
                                                 std::make_shared<tls::Session_Manager_Noop>(),
                                                 std::make_shared<Example_Policy>(),
                                                 tls::Server_Information(host));
   tls::Datagram datagram(std::move(context), std::move(socket));

   co_await datagram.async_handshake(tls::Connection_Side::Client, net::use_awaitable);
   co_await datagram.async_send(net::buffer(message), net::use_awaitable);
   std::array<char, 16384> reply{};
   const auto received = co_await datagram.async_receive(net::buffer(reply), net::use_awaitable);
   std::cout.write(reply.data(), static_cast<std::streamsize>(received));
   co_await datagram.async_shutdown(net::use_awaitable);
};

}  // namespace

int main(int argc, char* argv[]) {
   if(argc != 5) {
      std::cerr << "Usage: dtls_datagram_client <host> <port> <ca-cert> <message>\n"
                << "Example:\n"
                << "    dtls_datagram_client 127.0.0.1 4433 ca.pem hello\n";
      return 1;
   }

   try {
      net::io_context io;
      // The coroutine, transport, and timeout all use the same strand.
      const auto strand = net::make_strand(io);
      net::steady_timer deadline(strand, std::chrono::seconds(30));
      net::cancellation_signal cancellation;

      deadline.async_wait([&cancellation](const boost::system::error_code& ec) {
         if(!ec) {
            cancellation.emit(net::cancellation_type::terminal);
         }
      });
      net::co_spawn(
         strand,
         [strand,
          host = std::string(argv[1]),
          port = std::string(argv[2]),
          ca_file = std::string(argv[3]),
          message = std::string(argv[4])]() mutable {
            return echo(strand, std::move(host), std::move(port), std::move(ca_file), std::move(message));
         },
         net::bind_cancellation_slot(cancellation.slot(), [&deadline](const std::exception_ptr& error) {
            deadline.cancel();
            if(error) {
               std::rethrow_exception(error);
            }
         }));
      io.run();
   } catch(const std::exception& e) {
      std::cerr << "Error: " << e.what() << '\n';
      return 1;
   }

   return 0;
}

#else

int main() {
   std::cerr << "This example requires Boost 1.81 or newer and Botan built with --with-boost, DTLS 1.2, "
                "and an auto seeded RNG.\n";
   return 1;
}

#endif
