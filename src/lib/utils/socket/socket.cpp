/*
* (C) 2015,2016,2017 Jack Lloyd
* (C) 2016 Daniel Neus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/socket.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/socket_asio.h>
#include <botan/internal/target_info.h>
#include <chrono>

#if defined(BOTAN_TARGET_OS_HAS_SOCKETS)
   #include <errno.h>
   #include <fcntl.h>
   #include <netdb.h>
   #include <netinet/in.h>
   #include <string.h>
   #include <sys/socket.h>
   #include <sys/time.h>
   #include <unistd.h>

#elif defined(BOTAN_TARGET_OS_HAS_WINSOCK2)
   #include <ws2tcpip.h>
#endif

namespace Botan {

namespace {

#if defined(BOTAN_TARGET_OS_HAS_SOCKETS) || defined(BOTAN_TARGET_OS_HAS_WINSOCK2)

class BSD_Socket final : public OS::Socket {
   private:
   #if defined(BOTAN_TARGET_OS_HAS_WINSOCK2)
      typedef SOCKET socket_type;
      typedef int socket_op_ret_type;
      typedef int socklen_type;
      typedef int sendrecv_len_type;

      static socket_type invalid_socket() { return INVALID_SOCKET; }

      static void close_socket(socket_type s) { ::closesocket(s); }

      static std::string get_last_socket_error() { return std::to_string(::WSAGetLastError()); }

      static bool nonblocking_connect_in_progress() { return (::WSAGetLastError() == WSAEWOULDBLOCK); }

      static void set_nonblocking(socket_type s) {
         u_long nonblocking = 1;
         ::ioctlsocket(s, FIONBIO, &nonblocking);
      }

      static void socket_init() {
         WSAData wsa_data;
         WORD wsa_version = MAKEWORD(2, 2);

         if(::WSAStartup(wsa_version, &wsa_data) != 0) {
            throw System_Error("WSAStartup() failed", WSAGetLastError());
         }

         if(LOBYTE(wsa_data.wVersion) != 2 || HIBYTE(wsa_data.wVersion) != 2) {
            ::WSACleanup();
            throw System_Error("Could not find a usable version of Winsock.dll");
         }
      }

      static void socket_fini() { ::WSACleanup(); }
   #else
      typedef int socket_type;
      typedef ssize_t socket_op_ret_type;
      typedef socklen_t socklen_type;
      typedef size_t sendrecv_len_type;

      static socket_type invalid_socket() { return -1; }

      static void close_socket(socket_type s) { ::close(s); }

      static std::string get_last_socket_error() { return ::strerror(errno); }

      static bool nonblocking_connect_in_progress() { return (errno == EINPROGRESS); }

      static void set_nonblocking(socket_type s) {
         if(::fcntl(s, F_SETFL, O_NONBLOCK) < 0) {
            throw System_Error("Setting socket to non-blocking state failed", errno);
         }
      }

      static void socket_init() {}

      static void socket_fini() {}
   #endif

   public:
      BSD_Socket(std::string_view hostname, std::string_view service, std::chrono::microseconds timeout) :
            m_timeout(timeout) {
         socket_init();

         m_socket = invalid_socket();

         addrinfo hints;
         clear_mem(&hints, 1);
         hints.ai_family = AF_UNSPEC;
         hints.ai_socktype = SOCK_STREAM;
         addrinfo* res;

         const std::string hostname_str(hostname);
         const std::string service_str(service);

         int rc = ::getaddrinfo(hostname_str.c_str(), service_str.c_str(), &hints, &res);

         if(rc != 0) {
            throw System_Error(fmt("Name resolution failed for {}", hostname), rc);
         }

         for(addrinfo* rp = res; (m_socket == invalid_socket()) && (rp != nullptr); rp = rp->ai_next) {
            if(rp->ai_family != AF_INET && rp->ai_family != AF_INET6) {
               continue;
            }

            m_socket = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

            if(m_socket == invalid_socket()) {
               // unsupported socket type?
               continue;
            }

            set_nonblocking(m_socket);

            int err = ::connect(m_socket, rp->ai_addr, static_cast<socklen_type>(rp->ai_addrlen));

            if(err == -1) {
               int active = 0;
               if(nonblocking_connect_in_progress()) {
                  struct timeval timeout_tv = make_timeout_tv();
                  fd_set write_set;
                  FD_ZERO(&write_set);
                  // Weirdly, Winsock uses a SOCKET type but wants FD_SET to get an int instead
                  FD_SET(static_cast<int>(m_socket), &write_set);

                  active = ::select(static_cast<int>(m_socket + 1), nullptr, &write_set, nullptr, &timeout_tv);

                  if(active) {
                     int socket_error = 0;
                     socklen_t len = sizeof(socket_error);

                     if(::getsockopt(m_socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&socket_error), &len) <
                        0) {
                        throw System_Error("Error calling getsockopt", errno);
                     }

                     if(socket_error != 0) {
                        active = 0;
                     }
                  }
               }

               if(active == 0) {
                  close_socket(m_socket);
                  m_socket = invalid_socket();
                  continue;
               }
            }
         }

         ::freeaddrinfo(res);

         if(m_socket == invalid_socket()) {
            throw System_Error(fmt("Connecting to {} for service {} failed with errno {}", hostname, service, errno),
                               errno);
         }
      }

      ~BSD_Socket() override {
         close_socket(m_socket);
         m_socket = invalid_socket();
         socket_fini();
      }

      BSD_Socket(const BSD_Socket& other) = delete;
      BSD_Socket(BSD_Socket&& other) = delete;
      BSD_Socket& operator=(const BSD_Socket& other) = delete;
      BSD_Socket& operator=(BSD_Socket&& other) = delete;

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
            socket_op_ret_type sent =
               ::send(m_socket, cast_uint8_ptr_to_char(&buf[sent_so_far]), static_cast<sendrecv_len_type>(left), 0);
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

         socket_op_ret_type got = ::recv(m_socket, cast_uint8_ptr_to_char(buf), static_cast<sendrecv_len_type>(len), 0);

         if(got < 0) {
            throw System_Error("Socket read failed", errno);
         }

         return static_cast<size_t>(got);
      }

   private:
      struct timeval make_timeout_tv() const {
         struct timeval tv;
         tv.tv_sec = static_cast<decltype(timeval::tv_sec)>(m_timeout.count() / 1000000);
         tv.tv_usec = static_cast<decltype(timeval::tv_usec)>(m_timeout.count() % 1000000);
         return tv;
      }

      const std::chrono::microseconds m_timeout;
      socket_type m_socket;
};

#endif

}  // namespace

std::unique_ptr<OS::Socket> OS::open_socket(std::string_view hostname,
                                            std::string_view service,
                                            std::chrono::milliseconds timeout) {
#if defined(BOTAN_HAS_BOOST_ASIO)
   return std::make_unique<Asio_Socket>(hostname, service, timeout);

#elif defined(BOTAN_TARGET_OS_HAS_SOCKETS) || defined(BOTAN_TARGET_OS_HAS_WINSOCK2)
   return std::make_unique<BSD_Socket>(hostname, service, timeout);

#else
   BOTAN_UNUSED(hostname, service, timeout);
   // No sockets for you
   return std::unique_ptr<Socket>();
#endif
}

}  // namespace Botan
