/*
* (C) 2015,2016,2017 Jack Lloyd
* (C) 2016 Daniel Neus
* (C) 2019 Nuno Goncalves <nunojpg@gmail.com>
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/socket_udp.h>
#include <botan/internal/uri.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>
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
#elif defined(BOTAN_TARGET_OS_HAS_SOCKETS)
   #include <sys/socket.h>
   #include <sys/time.h>
   #include <netinet/in.h>
   #include <netdb.h>
   #include <string.h>
   #include <unistd.h>
   #include <errno.h>
   #include <fcntl.h>

#elif defined(BOTAN_TARGET_OS_HAS_WINSOCK2)
   #include <ws2tcpip.h>
#endif

namespace Botan {

namespace {

#if defined(BOTAN_HAS_BOOST_ASIO)
class Asio_SocketUDP final : public OS::SocketUDP
   {
   public:
      Asio_SocketUDP(const std::string& hostname,
                     const std::string& service,
                     std::chrono::microseconds timeout) :
         m_timeout(timeout), m_timer(m_io), m_udp(m_io)
         {
         m_timer.expires_from_now(m_timeout);
         check_timeout();

         boost::asio::ip::udp::resolver resolver(m_io);
         boost::asio::ip::udp::resolver::query query(hostname, service);
         boost::asio::ip::udp::resolver::iterator dns_iter = resolver.resolve(query);

         boost::system::error_code ec = boost::asio::error::would_block;

         auto connect_cb = [&ec](const boost::system::error_code& e,
         boost::asio::ip::udp::resolver::iterator) { ec = e; };

         boost::asio::async_connect(m_udp, dns_iter, connect_cb);

         while(ec == boost::asio::error::would_block)
            {
            m_io.run_one();
            }

         if(ec)
            { throw boost::system::system_error(ec); }
         if(m_udp.is_open() == false)
            { throw System_Error("Connection to host " + hostname + " failed"); }
         }

      void write(const uint8_t buf[], size_t len) override
         {
         m_timer.expires_from_now(m_timeout);

         boost::system::error_code ec = boost::asio::error::would_block;

         m_udp.async_send(boost::asio::buffer(buf, len),
         [&ec](boost::system::error_code e, size_t) { ec = e; });

         while(ec == boost::asio::error::would_block)
            {
            m_io.run_one();
            }

         if(ec)
            {
            throw boost::system::system_error(ec);
            }
         }

      size_t read(uint8_t buf[], size_t len) override
         {
         m_timer.expires_from_now(m_timeout);

         boost::system::error_code ec = boost::asio::error::would_block;
         size_t got = 0;

         m_udp.async_receive(boost::asio::buffer(buf, len),
         [&](boost::system::error_code cb_ec, size_t cb_got) { ec = cb_ec; got = cb_got; });

         while(ec == boost::asio::error::would_block)
            {
            m_io.run_one();
            }

         if(ec)
            {
            if(ec == boost::asio::error::eof)
               { return 0; }
            throw boost::system::system_error(ec); // Some other error.
            }

         return got;
         }

   private:
      void check_timeout()
         {
         if(m_udp.is_open() && m_timer.expires_at() < std::chrono::system_clock::now())
            {
            boost::system::error_code err;
            m_udp.close(err);
            }

         m_timer.async_wait(std::bind(&Asio_SocketUDP::check_timeout, this));
         }

      const std::chrono::microseconds m_timeout;
      boost::asio::io_service m_io;
      boost::asio::system_timer m_timer;
      boost::asio::ip::udp::socket m_udp;
   };
#elif defined(BOTAN_TARGET_OS_HAS_SOCKETS) || defined(BOTAN_TARGET_OS_HAS_WINSOCK2)
class BSD_SocketUDP final : public OS::SocketUDP
   {
   public:
      BSD_SocketUDP(const std::string& hostname,
                    const std::string& service,
                    std::chrono::microseconds timeout) : m_timeout(timeout)
         {
         socket_init();

         m_socket = invalid_socket();

         addrinfo* res;
         addrinfo hints;
         clear_mem(&hints, 1);
         hints.ai_family = AF_UNSPEC;
         hints.ai_socktype = SOCK_DGRAM;

         int rc = ::getaddrinfo(hostname.c_str(), service.c_str(), &hints, &res);

         if(rc != 0)
            {
            throw System_Error("Name resolution failed for " + hostname, rc);
            }

         for(addrinfo* rp = res; (m_socket == invalid_socket()) && (rp != nullptr); rp = rp->ai_next)
            {
            if(rp->ai_family != AF_INET && rp->ai_family != AF_INET6)
               { continue; }

            m_socket = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

            if(m_socket == invalid_socket())
               {
               // unsupported socket type?
               continue;
               }

            set_nonblocking(m_socket);
            memcpy(&sa, res->ai_addr, res->ai_addrlen);
            salen = static_cast<socklen_t>(res->ai_addrlen);
            }

         ::freeaddrinfo(res);

         if(m_socket == invalid_socket())
            {
            throw System_Error("Connecting to " + hostname +
                               " for service " + service + " failed", errno);
            }
         }

      ~BSD_SocketUDP()
         {
         close_socket(m_socket);
         m_socket = invalid_socket();
         socket_fini();
         }

      void write(const uint8_t buf[], size_t len) override
         {
         fd_set write_set;
         FD_ZERO(&write_set);
         FD_SET(m_socket, &write_set);

         size_t sent_so_far = 0;
         while(sent_so_far != len)
            {
            struct timeval timeout = make_timeout_tv();
            int active = ::select(static_cast<int>(m_socket + 1), nullptr, &write_set, nullptr, &timeout);

            if(active == 0)
               { throw System_Error("Timeout during socket write"); }

            const size_t left = len - sent_so_far;
            socket_op_ret_type sent = ::sendto(m_socket, cast_uint8_ptr_to_char(buf + sent_so_far),
                                               static_cast<sendrecv_len_type>(left), 0,
                                               reinterpret_cast<sockaddr*>(&sa), salen);
            if(sent < 0)
               { throw System_Error("Socket write failed", errno); }
            else
               { sent_so_far += static_cast<size_t>(sent); }
            }
         }

      size_t read(uint8_t buf[], size_t len) override
         {
         fd_set read_set;
         FD_ZERO(&read_set);
         FD_SET(m_socket, &read_set);

         struct timeval timeout = make_timeout_tv();
         int active = ::select(static_cast<int>(m_socket + 1), &read_set, nullptr, nullptr, &timeout);

         if(active == 0)
            { throw System_Error("Timeout during socket read"); }

         socket_op_ret_type got = ::recvfrom(m_socket, cast_uint8_ptr_to_char(buf), static_cast<sendrecv_len_type>(len), 0, nullptr, nullptr);

         if(got < 0)
            { throw System_Error("Socket read failed", errno); }

         return static_cast<size_t>(got);
         }

   private:
#if defined(BOTAN_TARGET_OS_HAS_WINSOCK2)
      typedef SOCKET socket_type;
      typedef int socket_op_ret_type;
      typedef int sendrecv_len_type;
      static socket_type invalid_socket() { return INVALID_SOCKET; }
      static void close_socket(socket_type s) { ::closesocket(s); }
      static std::string get_last_socket_error() { return std::to_string(::WSAGetLastError()); }

      static bool nonblocking_connect_in_progress()
         {
         return (::WSAGetLastError() == WSAEWOULDBLOCK);
         }

      static void set_nonblocking(socket_type s)
         {
         u_long nonblocking = 1;
         ::ioctlsocket(s, FIONBIO, &nonblocking);
         }

      static void socket_init()
         {
         WSAData wsa_data;
         WORD wsa_version = MAKEWORD(2, 2);

         if(::WSAStartup(wsa_version, &wsa_data) != 0)
            {
            throw System_Error("WSAStartup() failed", WSAGetLastError());
            }

         if(LOBYTE(wsa_data.wVersion) != 2 || HIBYTE(wsa_data.wVersion) != 2)
            {
            ::WSACleanup();
            throw System_Error("Could not find a usable version of Winsock.dll");
            }
         }

      static void socket_fini()
         {
         ::WSACleanup();
         }
#else
      typedef int socket_type;
      typedef ssize_t socket_op_ret_type;
      typedef size_t sendrecv_len_type;
      static socket_type invalid_socket() { return -1; }
      static void close_socket(socket_type s) { ::close(s); }
      static std::string get_last_socket_error() { return ::strerror(errno); }
      static bool nonblocking_connect_in_progress() { return (errno == EINPROGRESS); }
      static void set_nonblocking(socket_type s)
         {
         if(::fcntl(s, F_SETFL, O_NONBLOCK) < 0)
            { throw System_Error("Setting socket to non-blocking state failed", errno); }
         }

      static void socket_init() {}
      static void socket_fini() {}
#endif
      sockaddr_storage sa;
      socklen_t salen;
      struct timeval make_timeout_tv() const
         {
         struct timeval tv;
         tv.tv_sec = static_cast<decltype(timeval::tv_sec)>(m_timeout.count() / 1000000);
         tv.tv_usec = static_cast<decltype(timeval::tv_usec)>(m_timeout.count() % 1000000);;
         return tv;
         }

      const std::chrono::microseconds m_timeout;
      socket_type m_socket;
   };
#endif
}

std::unique_ptr<OS::SocketUDP>
OS::open_socket_udp(const std::string& hostname,
                    const std::string& service,
                    std::chrono::microseconds timeout)
   {
#if defined(BOTAN_HAS_BOOST_ASIO)
   return std::unique_ptr<OS::SocketUDP>(new Asio_SocketUDP(hostname, service, timeout));
#elif defined(BOTAN_TARGET_OS_HAS_SOCKETS) || defined(BOTAN_TARGET_OS_HAS_WINSOCK2)
   return std::unique_ptr<OS::SocketUDP>(new BSD_SocketUDP(hostname, service, timeout));
#else
   BOTAN_UNUSED(hostname);
   BOTAN_UNUSED(service);
   BOTAN_UNUSED(timeout);
   return std::unique_ptr<OS::SocketUDP>();
#endif
   }

std::unique_ptr<OS::SocketUDP>
OS::open_socket_udp(const std::string& uri_string,
                    std::chrono::microseconds timeout)
   {
   const auto uri = URI::fromAny(uri_string);
   if(uri.port == 0)
      { throw Invalid_Argument("UDP port not specified"); }
   return open_socket_udp(uri.host, std::to_string(uri.port), timeout);
   }

}
