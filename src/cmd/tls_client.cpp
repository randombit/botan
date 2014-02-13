#include "apps.h"

#if defined(BOTAN_HAS_TLS)
#include <botan/tls_client.h>
#include <botan/pkcs8.h>
#include <botan/hex.h>
#include <string>
#include <iostream>
#include <memory>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#if !defined(MSG_NOSIGNAL)
  #define MSG_NOSIGNAL 0
#endif

#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
  #include <botan/tls_session_manager_sqlite.h>
#endif

#include "credentials.h"

using namespace Botan;

using namespace std::placeholders;

namespace {

int connect_to_host(const std::string& host, u16bit port, const std::string& transport)
   {
   hostent* host_addr = ::gethostbyname(host.c_str());

   if(!host_addr)
      throw std::runtime_error("gethostbyname failed for " + host);

   if(host_addr->h_addrtype != AF_INET) // FIXME
      throw std::runtime_error(host + " has IPv6 address, not supported");

   int type = (transport == "tcp") ? SOCK_STREAM : SOCK_DGRAM;

   int fd = ::socket(PF_INET, type, 0);
   if(fd == -1)
      throw std::runtime_error("Unable to acquire socket");

   sockaddr_in socket_info;
   ::memset(&socket_info, 0, sizeof(socket_info));
   socket_info.sin_family = AF_INET;
   socket_info.sin_port = htons(port);

   ::memcpy(&socket_info.sin_addr,
            host_addr->h_addr,
            host_addr->h_length);

   socket_info.sin_addr = *(struct in_addr*)host_addr->h_addr; // FIXME

   if(::connect(fd, (sockaddr*)&socket_info, sizeof(struct sockaddr)) != 0)
      {
      ::close(fd);
      throw std::runtime_error("connect failed");
      }

   return fd;
   }

bool handshake_complete(const TLS::Session& session)
   {
   std::cout << "Handshake complete, " << session.version().to_string()
             << " using " << session.ciphersuite().to_string() << "\n";

   if(!session.session_id().empty())
      std::cout << "Session ID " << hex_encode(session.session_id()) << "\n";

   if(!session.session_ticket().empty())
      std::cout << "Session ticket " << hex_encode(session.session_ticket()) << "\n";

   return true;
   }

void dgram_socket_write(int sockfd, const byte buf[], size_t length)
   {
   send(sockfd, buf, length, MSG_NOSIGNAL);
   }

void stream_socket_write(int sockfd, const byte buf[], size_t length)
   {
   size_t offset = 0;

   while(length)
      {
      ssize_t sent = ::send(sockfd, (const char*)buf + offset,
                            length, MSG_NOSIGNAL);

      if(sent == -1)
         {
         if(errno == EINTR)
            sent = 0;
         else
            throw std::runtime_error("Socket::write: Socket write failed");
         }

      offset += sent;
      length -= sent;
      }
   }

bool got_alert = false;

void alert_received(TLS::Alert alert, const byte [], size_t )
   {
   std::cout << "Alert: " << alert.type_string() << "\n";
   got_alert = true;
   }

void process_data(const byte buf[], size_t buf_size)
   {
   for(size_t i = 0; i != buf_size; ++i)
      std::cout << buf[i];
   }

std::string protocol_chooser(const std::vector<std::string>& protocols)
   {
   for(size_t i = 0; i != protocols.size(); ++i)
      std::cout << "Protocol " << i << " = " << protocols[i] << "\n";
   return "http/1.1";
   }

}

int tls_client_main(int argc, char* argv[])
   {
   if(argc != 2 && argc != 3 && argc != 4)
      {
      std::cout << "Usage " << argv[0] << " host [port] [udp|tcp]\n";
      return 1;
      }

   try
      {
      AutoSeeded_RNG rng;
      TLS::Policy policy;

#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
      TLS::Session_Manager_SQLite session_manager("my secret passphrase",
                                                  rng,
                                                  "sessions.db");
#else
      TLS::Session_Manager_In_Memory session_manager(rng);
#endif

      Credentials_Manager_Simple creds(rng);

      std::string host = argv[1];
      u32bit port = argc >= 3 ? Botan::to_u32bit(argv[2]) : 443;
      std::string transport = argc >= 4 ? argv[3] : "tcp";

      int sockfd = connect_to_host(host, port, transport);

      auto socket_write =
         (transport == "tcp") ?
         std::bind(stream_socket_write, sockfd, _1, _2) :
         std::bind(dgram_socket_write, sockfd, _1, _2);

      auto version =
         (transport == "tcp") ?
         TLS::Protocol_Version::latest_tls_version() :
         TLS::Protocol_Version::latest_dtls_version();

      TLS::Client client(socket_write,
                         process_data,
                         alert_received,
                         handshake_complete,
                         session_manager,
                         creds,
                         policy,
                         rng,
                         TLS::Server_Information(host, port),
                         version,
                         protocol_chooser);

      while(!client.is_closed())
         {
         fd_set readfds;
         FD_ZERO(&readfds);
         FD_SET(sockfd, &readfds);
         FD_SET(STDIN_FILENO, &readfds);

         ::select(sockfd + 1, &readfds, nullptr, nullptr, nullptr);

         if(FD_ISSET(sockfd, &readfds))
            {
            byte buf[4*1024] = { 0 };

            ssize_t got = ::read(sockfd, buf, sizeof(buf));

            if(got == 0)
               {
               std::cout << "EOF on socket\n";
               break;
               }
            else if(got == -1)
               {
               std::cout << "Socket error: " << errno << " " << strerror(errno) << "\n";
               continue;
               }

            //std::cout << "Socket - got " << got << " bytes\n";
            client.received_data(buf, got);
            }
         else if(FD_ISSET(STDIN_FILENO, &readfds))
            {
            byte buf[1024] = { 0 };
            ssize_t got = read(STDIN_FILENO, buf, sizeof(buf));

            if(got == 0)
               {
               std::cout << "EOF on stdin\n";
               client.close();
               break;
               }
            else if(got == -1)
               {
               std::cout << "Stdin error: " << errno << " " << strerror(errno) << "\n";
               continue;
               }

            if(got == 2 && buf[1] == '\n')
               {
               char cmd = buf[0];

               if(cmd == 'R' || cmd == 'r')
                  {
                  std::cout << "Client initiated renegotiation\n";
                  client.renegotiate(cmd == 'R');
                  }
               else if(cmd == 'Q')
                  {
                  std::cout << "Client initiated close\n";
                  client.close();
                  }
               }
            else if(buf[0] == 'H')
               client.heartbeat(&buf[1], got-1);
            else
               client.send(buf, got);
            }
         }

      ::close(sockfd);

   }
   catch(std::exception& e)
      {
      std::cout << "Exception: " << e.what() << "\n";
      return 1;
      }
   return 0;
   }

#endif
