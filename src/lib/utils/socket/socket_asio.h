/*
* (C) 2015,2016,2017 Jack Lloyd
* (C) 2016 Daniel Neus
* (C) 2019 Nuno Goncalves <nunojpg@gmail.com>
* (C) 2025 Kagan Can Sit
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SOCKET_ASIO_H_
#define BOTAN_SOCKET_ASIO_H_

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/socket.h>
#include <botan/internal/socket_udp.h>
#include <chrono>

#if defined(BOTAN_HAS_BOOST_ASIO)
   /*
  * We don't need serial port support anyway, and asking for it causes
  * macro conflicts with termios.h when this file is included in the
  * amalgamation.
  */
   #define BOOST_ASIO_DISABLE_SERIAL_PORT
   #include <boost/asio.hpp>
   #include <boost/asio/system_timer.hpp>
#endif

namespace Botan::OS {

#if defined(BOTAN_HAS_BOOST_ASIO)

/*
 * A template-based implementation of Asio sockets that can be used
 * for both TCP and UDP protocols, reducing code duplication.
 *
 * @param BaseSocketType The base socket class (Socket for TCP, SocketUDP for UDP)
 * @param ProtocolType The Asio protocol type (boost::asio::ip::tcp or boost::asio::ip::udp)
 */
template <typename BaseSocketType, typename ProtocolType>
class Asio_Socket_Base : public BaseSocketType {
   public:
      Asio_Socket_Base(std::string_view hostname, std::string_view service, std::chrono::milliseconds timeout) :
            // Convert milliseconds to microseconds for consistent timing operations
            m_timeout(std::chrono::duration_cast<std::chrono::microseconds>(timeout)), m_timer(m_io), m_socket(m_io) {
         m_timer.expires_after(m_timeout);
         check_timeout();

         // Resolve the DNS
         typename ProtocolType::resolver resolver(m_io);
         auto endPoints = resolver.resolve(std::string{hostname}, std::string{service});

         boost::system::error_code ec = boost::asio::error::would_block;

         auto connect_cb = [&ec](const boost::system::error_code& e, const typename ProtocolType::endpoint&) {
            ec = e;
         };

         boost::asio::async_connect(m_socket, endPoints, connect_cb);

         while(ec == boost::asio::error::would_block) {
            m_io.run_one();
         }

         if(ec) {
            throw boost::system::system_error(ec);
         }

         if(m_socket.is_open() == false) {
            throw System_Error(fmt("Connection to host {} failed", hostname));
         }
      }

      void write(const uint8_t buf[], size_t len) override {
         m_timer.expires_after(m_timeout);

         boost::system::error_code ec = boost::asio::error::would_block;

         m_socket.async_send(boost::asio::buffer(buf, len), [&ec](boost::system::error_code e, size_t) { ec = e; });

         while(ec == boost::asio::error::would_block) {
            m_io.run_one();
         }

         if(ec) {
            throw boost::system::system_error(ec);
         }
      }

      size_t read(uint8_t buf[], size_t len) override {
         m_timer.expires_after(m_timeout);

         boost::system::error_code ec = boost::asio::error::would_block;
         size_t got = 0;

         // Use different read methods based on protocol type
         if constexpr(std::is_same_v<ProtocolType, boost::asio::ip::tcp>) {
            m_socket.async_read_some(boost::asio::buffer(buf, len),
                                     [&](boost::system::error_code cb_ec, size_t cb_got) {
                                        ec = cb_ec;
                                        got = cb_got;
                                     });
         } else if constexpr(std::is_same_v<ProtocolType, boost::asio::ip::udp>) {
            m_socket.async_receive(boost::asio::buffer(buf, len), [&](boost::system::error_code cb_ec, size_t cb_got) {
               ec = cb_ec;
               got = cb_got;
            });
         }

         while(ec == boost::asio::error::would_block) {
            m_io.run_one();
         }

         if(ec) {
            if(ec == boost::asio::error::eof) {
               return 0;
            }
            throw boost::system::system_error(ec);  // Some other error.
         }

         return got;
      }

   private:
      void check_timeout() {
         if(m_socket.is_open() && m_timer.expiry() < std::chrono::system_clock::now()) {
            boost::system::error_code err;

            // NOLINTNEXTLINE(bugprone-unused-return-value,cert-err33-c)
            m_socket.close(err);
         }

         m_timer.async_wait(std::bind(&Asio_Socket_Base::check_timeout, this));
      }

      const std::chrono::microseconds m_timeout;
      boost::asio::io_context m_io;
      boost::asio::system_timer m_timer;
      typename ProtocolType::socket m_socket;
};

// Convenience type aliases for common socket types
using Asio_Socket = Asio_Socket_Base<Socket, boost::asio::ip::tcp>;
using Asio_SocketUDP = Asio_Socket_Base<SocketUDP, boost::asio::ip::udp>;

#endif  // BOTAN_HAS_BOOST_ASIO

}  // namespace Botan::OS

#endif  // BOTAN_SOCKET_ASIO_H_
