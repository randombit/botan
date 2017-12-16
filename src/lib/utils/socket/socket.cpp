/*
* (C) 2015,2016,2017 Jack Lloyd
* (C) 2016 Daniel Neus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/socket.h>
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

#elif defined(BOTAN_TARGET_OS_TYPE_IS_UNIX)
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <string.h>
  #include <unistd.h>
  #include <errno.h>

#elif defined(BOTAN_TARGET_OS_TYPE_IS_WINDOWS)
  #define NOMINMAX 1
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
#endif

namespace Botan {

namespace {

#if defined(BOTAN_HAS_BOOST_ASIO)

class Asio_Socket final : public OS::Socket
   {
   public:
      Asio_Socket(const std::string& hostname,
                  const std::string& service,
                  std::chrono::milliseconds timeout) :
         m_timeout(timeout), m_timer(m_io), m_tcp(m_io)
         {
         m_timer.expires_from_now(m_timeout);
         check_timeout();

         boost::asio::ip::tcp::resolver resolver(m_io);
         boost::asio::ip::tcp::resolver::query query(hostname, service);
         boost::asio::ip::tcp::resolver::iterator dns_iter = resolver.resolve(query);

         boost::system::error_code ec = boost::asio::error::would_block;

         auto connect_cb = [&ec](const boost::system::error_code& e,
                                 boost::asio::ip::tcp::resolver::iterator) { ec = e; };

         boost::asio::async_connect(m_tcp, dns_iter, connect_cb);

         while(ec == boost::asio::error::would_block)
            {
            m_io.run_one();
            }

         if(ec)
            throw boost::system::system_error(ec);
         if(ec || m_tcp.is_open() == false)
            throw Exception("Connection to host " + hostname + " failed");
         }

      void write(const uint8_t buf[], size_t len) override
         {
         m_timer.expires_from_now(m_timeout);

         boost::system::error_code ec = boost::asio::error::would_block;

         boost::asio::async_write(m_tcp, boost::asio::buffer(buf, len),
                                  [&ec](boost::system::error_code e, size_t got) { printf("wrote %d\n", got); ec = e; });

         while(ec == boost::asio::error::would_block) { m_io.run_one(); }

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

         auto read_cb = [&](const boost::system::error_code cb_ec, size_t cb_got) {
            ec = cb_ec; got = cb_got;
         };

         m_tcp.async_read_some(boost::asio::buffer(buf, len), read_cb);

         while(ec == boost::asio::error::would_block) { m_io.run_one(); }

         if(ec)
            {
            if(ec == boost::asio::error::eof)
               return 0;
            throw boost::system::system_error(ec); // Some other error.
            }

         return got;
         }

   private:
      void check_timeout()
         {
         if(m_tcp.is_open() && m_timer.expires_at() < std::chrono::system_clock::now())
            {
            boost::system::error_code err;
            m_tcp.close(err);
            }

         m_timer.async_wait(std::bind(&Asio_Socket::check_timeout, this));
         }

      const std::chrono::milliseconds m_timeout;
      boost::asio::io_service m_io;
      boost::asio::system_timer m_timer;
      boost::asio::ip::tcp::socket m_tcp;
   };

#elif defined(BOTAN_TARGET_OS_TYPE_IS_WINDOWS)

class Winsock_Socket final : public OS::Socket
   {
   public:
      Winsock_Socket(const std::string& hostname, const std::string& service)
         {
         WSAData wsa_data;
         WORD wsa_version = MAKEWORD(2, 2);

         if (::WSAStartup(wsa_version, &wsa_data) != 0)
            {
            throw Exception("WSAStartup() failed: " + std::to_string(WSAGetLastError()));
            }

         if (LOBYTE(wsa_data.wVersion) != 2 || HIBYTE(wsa_data.wVersion) != 2)
            {
            ::WSACleanup();
            throw Exception("Could not find a usable version of Winsock.dll");
            }

         addrinfo hints;
         ::memset(&hints, 0, sizeof(addrinfo));
         hints.ai_family = AF_UNSPEC;
         hints.ai_socktype = SOCK_STREAM;
         addrinfo* res;

         if(::getaddrinfo(hostname.c_str(), service.c_str(), &hints, &res) != 0)
            {
            throw Exception("Name resolution failed for " + hostname);
            }

         for(addrinfo* rp = res; (m_socket == INVALID_SOCKET) && (rp != nullptr); rp = rp->ai_next)
            {
            m_socket = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

            // unsupported socket type?
            if(m_socket == INVALID_SOCKET)
               continue;

            if(::connect(m_socket, rp->ai_addr, rp->ai_addrlen) != 0)
               {
               ::closesocket(m_socket);
               m_socket = INVALID_SOCKET;
               continue;
               }
            }

         ::freeaddrinfo(res);

         if(m_socket == INVALID_SOCKET)
            {
            throw Exception("Connecting to " + hostname +
                            " for service " + service + " failed");
            }
         }

      ~Winsock_Socket()
         {
         ::closesocket(m_socket);
         m_socket = INVALID_SOCKET;
         ::WSACleanup();
         }

      void write(const uint8_t buf[], size_t len) override
         {
         size_t sent_so_far = 0;
         while(sent_so_far != len)
            {
            const size_t left = len - sent_so_far;
            int sent = ::send(m_socket,
                              cast_uint8_ptr_to_char(buf + sent_so_far),
                              static_cast<int>(left),
                              0);

            if(sent == SOCKET_ERROR)
               throw Exception("Socket write failed with error " +
                               std::to_string(::WSAGetLastError()));
            else
               sent_so_far += static_cast<size_t>(sent);
            }
         }

      size_t read(uint8_t buf[], size_t len) override
         {
         int got = ::recv(m_socket,
                          cast_uint8_ptr_to_char(buf),
                          static_cast<int>(len), 0);

         if(got == SOCKET_ERROR)
            throw Exception("Socket read failed with error " +
                            std::to_string(::WSAGetLastError()));
         return static_cast<size_t>(got);
         }

   private:
      SOCKET m_socket = INVALID_SOCKET;
   };

#elif defined(BOTAN_TARGET_OS_TYPE_IS_UNIX)
class BSD_Socket final : public OS::Socket
   {
   public:
      BSD_Socket(const std::string& hostname,
                 const std::string& service,
                 std::chrono::microseconds timeout) : m_timeout(timeout)
         {
         addrinfo hints;
         ::memset(&hints, 0, sizeof(addrinfo));
         hints.ai_family = AF_UNSPEC;
         hints.ai_socktype = SOCK_STREAM;
         addrinfo* res;

         if(::getaddrinfo(hostname.c_str(), service.c_str(), &hints, &res) != 0)
            {
            throw Exception("Name resolution failed for " + hostname);
            }

         m_fd = -1;

         for(addrinfo* rp = res; (m_fd < 0) && (rp != nullptr); rp = rp->ai_next)
            {
            m_fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

            if(m_fd < 0)
               {
               // unsupported socket type?
               continue;
               }

            if(::connect(m_fd, rp->ai_addr, rp->ai_addrlen) != 0)
               {
               ::close(m_fd);
               m_fd = -1;
               continue;
               }
            }

         ::freeaddrinfo(res);

         if(m_fd < 0)
            {
            throw Exception("Connecting to " + hostname +
                            " for service " + service + " failed");
            }
         }

      ~BSD_Socket()
         {
         ::close(m_fd);
         m_fd = -1;
         }


      void write(const uint8_t buf[], size_t len) override
         {
         size_t sent_so_far = 0;
         while(sent_so_far != len)
            {
            const size_t left = len - sent_so_far;
            ssize_t sent = ::write(m_fd, &buf[sent_so_far], left);
            if(sent < 0)
               throw Exception("Socket write failed with error '" +
                               std::string(::strerror(errno)) + "'");
            else
               sent_so_far += static_cast<size_t>(sent);
            }
         }

      size_t read(uint8_t buf[], size_t len) override
         {
         ssize_t got = ::read(m_fd, buf, len);

         if(got < 0)
            throw Exception("Socket read failed with error '" +
                            std::string(::strerror(errno)) + "'");
         return static_cast<size_t>(got);
         }

   private:
      struct timeval make_timeout_tv() const
         {
         struct timeval tv;
         tv.tv_sec = m_timeout.count() / 1000000;
         tv.tv_usec = m_timeout.count() % 1000000;
         return tv;
         }

      const std::chrono::microseconds m_timeout;
      int m_fd;
   };

#endif

}

std::unique_ptr<OS::Socket>
OS::open_socket(const std::string& hostname,
                const std::string& service,
                std::chrono::milliseconds timeout)
   {
#if defined(BOTAN_HAS_BOOST_ASIO)
   return std::unique_ptr<OS::Socket>(new Asio_Socket(hostname, service, timeout));

#elif defined(BOTAN_TARGET_OS_TYPE_IS_WINDOWS)
   return std::unique_ptr<OS::Socket>(new Winsock_Socket(hostname, service));

#elif defined(BOTAN_TARGET_OS_TYPE_IS_UNIX)
   return std::unique_ptr<OS::Socket>(new BSD_Socket(hostname, service, timeout));

#else
   // No sockets for you
   return std::unique_ptr<Socket>();
#endif
   }

}
