/*
* (C) 2015,2016,2017 Jack Lloyd
* (C) 2016 Daniel Neus
* (C) 2019 Nuno Goncalves <nunojpg@gmail.com>
* (C) 2025 Kagan Can Sit
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/socket_udp.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/socket_platform.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/target_info.h>
#include <botan/internal/uri.h>
#include <chrono>

#if defined(BOTAN_HAS_BOOST_ASIO)
   /*
   * We don't need serial port support anyway, and asking for it
   * causes macro conflicts with Darwin's termios.h when this
   * file is included in the amalgamation. GH #350
   */
   #define BOOST_ASIO_DISABLE_SERIAL_PORT
   #include <boost/asio.hpp>
   #include <boost/asio/system_timer.hpp>
#endif

namespace Botan {

namespace {

#if defined(BOTAN_HAS_BOOST_ASIO)
class Asio_SocketUDP final : public OS::SocketUDP {
   public:
      Asio_SocketUDP(std::string_view hostname, std::string_view service, std::chrono::microseconds timeout) :
            m_timeout(timeout), m_timer(m_io), m_udp(m_io) {
         m_timer.expires_after(m_timeout);
         check_timeout();

         boost::asio::ip::udp::resolver resolver(m_io);
         boost::asio::ip::udp::resolver::results_type dns_iter =
            resolver.resolve(std::string{hostname}, std::string{service});

         boost::system::error_code ec = boost::asio::error::would_block;

         auto connect_cb = [&ec](const boost::system::error_code& e,
                                 const boost::asio::ip::udp::resolver::results_type::iterator&) { ec = e; };

         boost::asio::async_connect(m_udp, dns_iter.begin(), dns_iter.end(), connect_cb);

         while(ec == boost::asio::error::would_block) {
            m_io.run_one();
         }

         if(ec) {
            throw boost::system::system_error(ec);
         }
         if(!m_udp.is_open()) {
            throw System_Error(fmt("Connection to host {} failed", hostname));
         }
      }

      void write(const uint8_t buf[], size_t len) override {
         m_timer.expires_after(m_timeout);

         boost::system::error_code ec = boost::asio::error::would_block;

         m_udp.async_send(boost::asio::buffer(buf, len), [&ec](boost::system::error_code e, size_t) { ec = e; });

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

         m_udp.async_receive(boost::asio::buffer(buf, len), [&](boost::system::error_code cb_ec, size_t cb_got) {
            ec = cb_ec;
            got = cb_got;
         });

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
         if(m_udp.is_open() && m_timer.expiry() < std::chrono::system_clock::now()) {
            boost::system::error_code err;

            // NOLINTNEXTLINE(bugprone-unused-return-value,cert-err33-c)
            m_udp.close(err);
         }

         // NOLINTNEXTLINE(*-avoid-bind) FIXME - unclear why we can't use a lambda here
         m_timer.async_wait(std::bind(&Asio_SocketUDP::check_timeout, this));
      }

      const std::chrono::microseconds m_timeout;
      boost::asio::io_context m_io;
      boost::asio::system_timer m_timer;
      boost::asio::ip::udp::socket m_udp;
};
#elif defined(BOTAN_TARGET_OS_HAS_SOCKETS) || defined(BOTAN_TARGET_OS_HAS_WINSOCK2)
class BSD_SocketUDP final : public OS::SocketUDP {
   public:
      BSD_SocketUDP(std::string_view hostname, std::string_view service, std::chrono::microseconds timeout) :
            m_timeout(timeout) {
         Botan::OS::Socket_Platform::socket_init();
         m_socket = Botan::OS::Socket_Platform::invalid_socket();

         addrinfo hints{};
         clear_mem(&hints, 1);
         hints.ai_family = AF_UNSPEC;
         hints.ai_socktype = SOCK_DGRAM;

         Botan::OS::Socket_Platform::unique_addrinfo_ptr res = nullptr;
         int rc =
            ::getaddrinfo(std::string(hostname).c_str(), std::string(service).c_str(), &hints, Botan::out_ptr(res));

         if(rc != 0) {
            throw System_Error(fmt("Name resolution failed for {}", hostname), rc);
         }

         for(addrinfo* rp = res.get(); (m_socket == Botan::OS::Socket_Platform::invalid_socket()) && rp != nullptr;
             rp = rp->ai_next) {
            if(rp->ai_family != AF_INET && rp->ai_family != AF_INET6) {
               continue;
            }

            m_socket = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

            if(m_socket == Botan::OS::Socket_Platform::invalid_socket()) [[unlikely]] {
               // unsupported socket type?
               continue;
            }

            Botan::OS::Socket_Platform::set_nonblocking(m_socket);
            memcpy(&m_sa, res->ai_addr, res->ai_addrlen);
            m_salen = static_cast<socklen_t>(res->ai_addrlen);  // NOLINT(*-redundant-casting)
         }

         if(m_socket == Botan::OS::Socket_Platform::invalid_socket()) {
            throw System_Error(fmt("Connecting to {} for service {} failed with errno {}", hostname, service, errno),
                               errno);
         }
      }

      ~BSD_SocketUDP() override {
         Botan::OS::Socket_Platform::close_socket(m_socket);
         m_socket = Botan::OS::Socket_Platform::invalid_socket();
         Botan::OS::Socket_Platform::socket_fini();
      }

      BSD_SocketUDP(const BSD_SocketUDP& other) = delete;
      BSD_SocketUDP(BSD_SocketUDP&& other) = delete;
      BSD_SocketUDP& operator=(const BSD_SocketUDP& other) = delete;
      BSD_SocketUDP& operator=(BSD_SocketUDP&& other) = delete;

      void write(const uint8_t buf[], size_t len) override {
         fd_set write_set;
         FD_ZERO(&write_set);
         FD_SET(m_socket, &write_set);

         size_t sent_so_far = 0;
         while(sent_so_far != len) {
            struct timeval timeout = make_timeout_tv();
            int active = ::select(static_cast<int>(m_socket + 1), nullptr, &write_set, nullptr, &timeout);

            if(active == 0) {
               throw System_Error("Timeout during socket write");
            }

            const size_t left = len - sent_so_far;
            socket_op_ret_type sent = ::sendto(m_socket,
                                               cast_uint8_ptr_to_char(buf + sent_so_far),
                                               static_cast<sendrecv_len_type>(left),
                                               0,
                                               reinterpret_cast<sockaddr*>(&m_sa),
                                               m_salen);
            if(sent < 0) {
               throw System_Error("Socket write failed", errno);
            } else {
               sent_so_far += static_cast<size_t>(sent);
            }
         }
      }

      size_t read(uint8_t buf[], size_t len) override {
         fd_set read_set;
         FD_ZERO(&read_set);
         FD_SET(m_socket, &read_set);

         struct timeval timeout = make_timeout_tv();
         int active = ::select(static_cast<int>(m_socket + 1), &read_set, nullptr, nullptr, &timeout);
         if(active == 0) {
            throw System_Error("Timeout during socket read");
         }

         socket_op_ret_type got =
            ::recv(m_socket, reinterpret_cast<char*>(buf), static_cast<sendrecv_len_type>(len), 0);
         if(got < 0) {
            throw System_Error("Socket read failed", errno);
         }

         return static_cast<size_t>(got);
      }

   private:
      // Import socket operation types from Socket_Platform namespace
      using socket_type = Botan::OS::Socket_Platform::socket_type;
      using socket_op_ret_type = Botan::OS::Socket_Platform::socket_op_ret_type;
      using socklen_type = Botan::OS::Socket_Platform::socklen_type;
      using sendrecv_len_type = Botan::OS::Socket_Platform::sendrecv_len_type;

      sockaddr_storage m_sa;
      socklen_t m_salen;

      struct timeval make_timeout_tv() const {
         struct timeval tv {};

         tv.tv_sec = static_cast<decltype(timeval::tv_sec)>(m_timeout.count() / 1000000);
         tv.tv_usec = static_cast<decltype(timeval::tv_usec)>(m_timeout.count() % 1000000);
         return tv;
      }

      const std::chrono::microseconds m_timeout;
      socket_type m_socket;
};
#endif
}  // namespace

std::unique_ptr<OS::SocketUDP> OS::open_socket_udp(std::string_view hostname,
                                                   std::string_view service,
                                                   std::chrono::microseconds timeout) {
#if defined(BOTAN_HAS_BOOST_ASIO)
   return std::make_unique<Asio_SocketUDP>(hostname, service, timeout);
#elif defined(BOTAN_TARGET_OS_HAS_SOCKETS) || defined(BOTAN_TARGET_OS_HAS_WINSOCK2)
   return std::make_unique<BSD_SocketUDP>(hostname, service, timeout);
#else
   BOTAN_UNUSED(hostname);
   BOTAN_UNUSED(service);
   BOTAN_UNUSED(timeout);
   return std::unique_ptr<OS::SocketUDP>();
#endif
}

std::unique_ptr<OS::SocketUDP> OS::open_socket_udp(std::string_view uri_string, std::chrono::microseconds timeout) {
   const auto uri = URI::from_any(uri_string);
   if(uri.port() == 0) {
      throw Invalid_Argument("UDP port not specified");
   }
   return open_socket_udp(uri.host(), std::to_string(uri.port()), timeout);
}

}  // namespace Botan
