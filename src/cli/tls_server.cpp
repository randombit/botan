/*
* TLS echo server using BSD sockets
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_TARGET_OS_HAS_SOCKETS)

#include <botan/tls_server.h>
#include <botan/hex.h>
#include "credentials.h"

#include <list>

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

namespace Botan_CLI {

class TLS_Server final : public Command
   {
   public:
      TLS_Server() : Command("tls_server cert key --port=443 --type=tcp --policy=") {}

      void go() override
         {
         const std::string server_crt = get_arg("cert");
         const std::string server_key = get_arg("key");
         const int port = get_arg_sz("port");
         const std::string transport = get_arg("type");

         if(transport != "tcp" && transport != "udp")
            throw CLI_Usage_Error("Invalid transport type '" + transport + "' for TLS");

         const bool is_tcp = (transport == "tcp");

         std::unique_ptr<Botan::TLS::Policy> policy;
         const std::string policy_file = get_arg("policy");
         std::filebuf fb;
         if(policy_file.size() > 0)
            {
            std::ifstream policy_stream(policy_file);
            if(!policy_stream.good())
               {
               error_output() << "Failed reading policy file\n";
               return;
               }
            policy.reset(new Botan::TLS::Text_Policy(policy_stream));
            }

         if(!policy)
            {
            policy.reset(new Botan::TLS::Policy);
            }

         Botan::TLS::Session_Manager_In_Memory session_manager(rng()); // TODO sqlite3

         Basic_Credentials_Manager creds(rng(), server_crt, server_key);

         auto protocol_chooser = [](const std::vector<std::string>& protocols) -> std::string {
            for(size_t i = 0; i != protocols.size(); ++i)
               std::cout << "Client offered protocol " << i << " = " << protocols[i] << std::endl;
            return "echo/1.0"; // too bad
         };

         output() << "Listening for new connections on " << transport << " port " << port << std::endl;

         int server_fd = make_server_socket(is_tcp, port);

         while(true)
            {
            int fd;

            if(is_tcp)
               fd = ::accept(server_fd, nullptr, nullptr);
            else
               {
               struct sockaddr_in from;
               socklen_t from_len = sizeof(sockaddr_in);

               if(::recvfrom(server_fd, nullptr, 0, MSG_PEEK,
                             reinterpret_cast<struct sockaddr*>(&from), &from_len) != 0)
                  throw CLI_Error("Could not peek next packet");

               if(::connect(server_fd, reinterpret_cast<struct sockaddr*>(&from), from_len) != 0)
                  throw CLI_Error("Could not connect UDP socket");

               fd = server_fd;
               }

            using namespace std::placeholders;

            auto socket_write = is_tcp ? std::bind(&stream_socket_write, fd, _1, _2) :
               std::bind(&dgram_socket_write, fd, _1, _2);

            std::string s;
            std::list<std::string> pending_output;

            auto proc_fn = [&](const uint8_t input[], size_t input_len)
               {
                  for(size_t i = 0; i != input_len; ++i)
                     {
                     const char c = static_cast<char>(input[i]);
                     s += c;
                     if(c == '\n')
                        {
                        pending_output.push_back(s);
                        s.clear();
                        }
                     }
               };

            Botan::TLS::Server server(socket_write,
                                      proc_fn,
                                      std::bind(&TLS_Server::alert_received, this, _1, _2, _3),
                                      std::bind(&TLS_Server::handshake_complete, this, _1),
                                      session_manager,
                                      creds,
                                      *policy,
                                      rng(),
                                      protocol_chooser,
                                      !is_tcp);

            try
               {
               while(!server.is_closed())
                  {
                  try 
                     {
                     uint8_t buf[4*1024] = { 0 };
                     ssize_t got = ::read(fd, buf, sizeof(buf));

                     if(got == -1)
                        {
                        std::cout << "Error in socket read - " << strerror(errno) << std::endl;
                        break;
                        }

                     if(got == 0)
                        {
                        std::cout << "EOF on socket" << std::endl;
                        break;
                        }

                     server.received_data(buf, got);

                     while(server.is_active() && !pending_output.empty())
                        {
                        std::string output = pending_output.front();
                        pending_output.pop_front();
                        server.send(output);

                        if(output == "quit\n")
                           server.close();
                        }
                     }
                  catch(std::exception& e) 
                     {
                     std::cout << "Connection1 problem: " << e.what() << std::endl;
                     if(is_tcp)
                        {
                        ::close(fd);
                        }
                     }
                  }
               }
            catch(Botan::Exception& e)
               {
               error_output() << "Connection failed: " << e.what() << "\n";
               }

            if(is_tcp)
               ::close(fd);
            }
         }
   private:
      int make_server_socket(bool is_tcp, uint16_t port)
         {
         const int type = is_tcp ? SOCK_STREAM : SOCK_DGRAM;

         int fd = ::socket(PF_INET, type, 0);
         if(fd == -1)
            throw CLI_Error("Unable to acquire socket");

         sockaddr_in socket_info;
         ::memset(&socket_info, 0, sizeof(socket_info));
         socket_info.sin_family = AF_INET;
         socket_info.sin_port = htons(port);

         // FIXME: support limiting listeners
         socket_info.sin_addr.s_addr = INADDR_ANY;

         if(::bind(fd, reinterpret_cast<struct sockaddr*>(&socket_info), sizeof(struct sockaddr)) != 0)
            {
            ::close(fd);
            throw CLI_Error("server bind failed");
            }

         if(is_tcp)
            {
            if(::listen(fd, 100) != 0)
               {
               ::close(fd);
               throw CLI_Error("listen failed");
               }
            }

         return fd;
         }

      bool handshake_complete(const Botan::TLS::Session& session)
         {
         std::cout << "Handshake complete, " << session.version().to_string()
                   << " using " << session.ciphersuite().to_string() << std::endl;

         if(!session.session_id().empty())
            std::cout << "Session ID " << Botan::hex_encode(session.session_id()) << std::endl;

         if(!session.session_ticket().empty())
            std::cout << "Session ticket " << Botan::hex_encode(session.session_ticket()) << std::endl;

         return true;
         }

      static void dgram_socket_write(int sockfd, const uint8_t buf[], size_t length)
         {
         ssize_t sent = ::send(sockfd, buf, length, MSG_NOSIGNAL);

         if(sent == -1)
            std::cout << "Error writing to socket - " << strerror(errno) << std::endl;
         else if(sent != static_cast<ssize_t>(length))
            std::cout << "Packet of length " << length << " truncated to " << sent << std::endl;
         }

      static void stream_socket_write(int sockfd, const uint8_t buf[], size_t length)
         {
         while(length)
            {
            ssize_t sent = ::send(sockfd, buf, length, MSG_NOSIGNAL);

            if(sent == -1)
               {
               if(errno == EINTR)
                  sent = 0;
               else
                  throw CLI_Error("Socket write failed");
               }

            buf += sent;
            length -= sent;
            }
         }

      void alert_received(Botan::TLS::Alert alert, const uint8_t[], size_t)
         {
         std::cout << "Alert: " << alert.type_string() << std::endl;
         }

   };

BOTAN_REGISTER_COMMAND("tls_server", TLS_Server);

}

#endif
