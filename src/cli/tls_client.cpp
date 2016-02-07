/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_TARGET_OS_HAS_SOCKETS)

#include <botan/tls_client.h>
#include <botan/hex.h>

#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
#include <botan/tls_session_manager_sqlite.h>
#endif

#include <string>
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

#include "credentials.h"

namespace Botan_CLI {

class TLS_Client final : public Command
   {
   public:
      TLS_Client() : Command("tls_client host --port=443 --type=tcp "
                             "--session-db= --session-db-pass= --next-protocols=") {}

      void go() override
         {
         Botan::TLS::Policy policy; // TODO read from a file

         // TODO client cert auth

         std::unique_ptr<Botan::TLS::Session_Manager> session_mgr;

#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
         const std::string sessions_passphrase = get_arg("session-db-pass");
         const std::string sessions_db = get_arg("session-db");

         if(!sessions_db.empty())
            {
            session_mgr.reset(new Botan::TLS::Session_Manager_SQLite(sessions_passphrase, rng(), sessions_db));
            }
#endif
         if(!session_mgr)
            {
            session_mgr.reset(new Botan::TLS::Session_Manager_In_Memory(rng()));
            }

         Basic_Credentials_Manager creds;

         const std::string host = get_arg("host");
         const uint16_t port = get_arg_sz("port");
         const std::string transport = get_arg("type");

         if(transport != "tcp" && transport != "udp")
            throw CLI_Usage_Error("Invalid transport type '" + transport + "' for TLS");

         const bool use_tcp = (transport == "tcp");

         const std::vector<std::string> protocols_to_offer = Botan::split_on("next-protocols", ',');

         int sockfd = connect_to_host(host, port, use_tcp);

         using namespace std::placeholders;

         auto socket_write =
            use_tcp ?
            std::bind(stream_socket_write, sockfd, _1, _2) :
            std::bind(dgram_socket_write, sockfd, _1, _2);

         auto version = policy.latest_supported_version(!use_tcp);

         Botan::TLS::Client client(socket_write,
                                   std::bind(&TLS_Client::process_data, this, _1, _2),
                                   std::bind(&TLS_Client::alert_received, this, _1, _2, _3),
                                   std::bind(&TLS_Client::handshake_complete, this, _1),
                                   *session_mgr,
                                   creds,
                                   policy,
                                   rng(),
                                   Botan::TLS::Server_Information(host, port),
                                   version,
                                   protocols_to_offer);

         bool first_active = true;

         while(!client.is_closed())
            {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(sockfd, &readfds);

            if(client.is_active())
               {
               FD_SET(STDIN_FILENO, &readfds);
               if(first_active && !protocols_to_offer.empty())
                  {
                  std::string app = client.application_protocol();
                  if(app != "")
                     output() << "Server choose protocol: " << client.application_protocol() << "\n";
                  first_active = false;
                  }
               }

            struct timeval timeout = { 1, 0 };

            ::select(sockfd + 1, &readfds, nullptr, nullptr, &timeout);

            if(FD_ISSET(sockfd, &readfds))
               {
               uint8_t buf[4*1024] = { 0 };

               ssize_t got = ::read(sockfd, buf, sizeof(buf));

               if(got == 0)
                  {
                  output() << "EOF on socket\n";
                  break;
                  }
               else if(got == -1)
                  {
                  output() << "Socket error: " << errno << " " << strerror(errno) << "\n";
                  continue;
                  }

               client.received_data(buf, got);
               }

            if(FD_ISSET(STDIN_FILENO, &readfds))
               {
               uint8_t buf[1024] = { 0 };
               ssize_t got = read(STDIN_FILENO, buf, sizeof(buf));

               if(got == 0)
                  {
                  output() << "EOF on stdin\n";
                  client.close();
                  break;
                  }
               else if(got == -1)
                  {
                  output() << "Stdin error: " << errno << " " << strerror(errno) << "\n";
                  continue;
                  }

               if(got == 2 && buf[1] == '\n')
                  {
                  char cmd = buf[0];

                  if(cmd == 'R' || cmd == 'r')
                     {
                     output() << "Client initiated renegotiation\n";
                     client.renegotiate(cmd == 'R');
                     }
                  else if(cmd == 'Q')
                     {
                     output() << "Client initiated close\n";
                     client.close();
                     }
                  }
               else
                  client.send(buf, got);
               }

            if(client.timeout_check())
               {
               output() << "Timeout detected\n";
               }
            }

         ::close(sockfd);
         }

   private:
      int connect_to_host(const std::string& host, uint16_t port, bool tcp)
         {
         hostent* host_addr = ::gethostbyname(host.c_str());

         if(!host_addr)
            throw CLI_Error("gethostbyname failed for " + host);

         if(host_addr->h_addrtype != AF_INET) // FIXME
            throw CLI_Error(host + " has IPv6 address, not supported");

         int type = tcp ? SOCK_STREAM : SOCK_DGRAM;

         int fd = ::socket(PF_INET, type, 0);
         if(fd == -1)
            throw CLI_Error("Unable to acquire socket");

         sockaddr_in socket_info;
         ::memset(&socket_info, 0, sizeof(socket_info));
         socket_info.sin_family = AF_INET;
         socket_info.sin_port = htons(port);

         ::memcpy(&socket_info.sin_addr,
                  host_addr->h_addr,
                  host_addr->h_length);

         socket_info.sin_addr = *reinterpret_cast<struct in_addr*>(host_addr->h_addr); // FIXME

         if(::connect(fd, (sockaddr*)&socket_info, sizeof(struct sockaddr)) != 0)
            {
            ::close(fd);
            throw CLI_Error("connect failed");
            }

         return fd;
         }

      bool handshake_complete(const Botan::TLS::Session& session)
         {
         output() << "Handshake complete, " << session.version().to_string()
                   << " using " << session.ciphersuite().to_string() << "\n";

         if(!session.session_id().empty())
            output() << "Session ID " << Botan::hex_encode(session.session_id()) << "\n";

         if(!session.session_ticket().empty())
            output() << "Session ticket " << Botan::hex_encode(session.session_ticket()) << "\n";

         return true;
         }

      static void dgram_socket_write(int sockfd, const uint8_t buf[], size_t length)
         {
         int r = send(sockfd, buf, length, MSG_NOSIGNAL);

         if(r == -1)
            throw CLI_Error("Socket write failed errno=" + std::to_string(errno));
         }

      static void stream_socket_write(int sockfd, const uint8_t buf[], size_t length)
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
                  throw CLI_Error("Socket write failed errno=" + std::to_string(errno));
               }

            offset += sent;
            length -= sent;
            }
         }

      void alert_received(Botan::TLS::Alert alert, const uint8_t [], size_t )
         {
         output() << "Alert: " << alert.type_string() << "\n";
         }

      void process_data(const uint8_t buf[], size_t buf_size)
         {
         for(size_t i = 0; i != buf_size; ++i)
            output() << buf[i];
         }
   };

BOTAN_REGISTER_COMMAND("tls_client", TLS_Client);

}

#endif
