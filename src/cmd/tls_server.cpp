/*
* TLS echo server using BSD sockets
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_TARGET_OS_HAS_SOCKETS)

#include <botan/tls_server.h>
#include <botan/hex.h>

#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/x509self.h>
#include <botan/secqueue.h>

#include "credentials.h"

using namespace Botan;

using namespace std::placeholders;

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

namespace {

int make_server_socket(bool is_tcp, u16bit port)
   {
   const int type = is_tcp ? SOCK_STREAM : SOCK_DGRAM;

   int fd = ::socket(PF_INET, type, 0);
   if(fd == -1)
      throw std::runtime_error("Unable to acquire socket");

   sockaddr_in socket_info;
   ::memset(&socket_info, 0, sizeof(socket_info));
   socket_info.sin_family = AF_INET;
   socket_info.sin_port = htons(port);

   // FIXME: support limiting listeners
   socket_info.sin_addr.s_addr = INADDR_ANY;

   if(::bind(fd, (sockaddr*)&socket_info, sizeof(struct sockaddr)) != 0)
      {
      ::close(fd);
      throw std::runtime_error("server bind failed");
      }

   if(is_tcp)
      {
      if(::listen(fd, 100) != 0)
         {
         ::close(fd);
         throw std::runtime_error("listen failed");
         }
      }

   return fd;
   }

bool handshake_complete(const TLS::Session& session)
   {
   std::cout << "Handshake complete, " << session.version().to_string()
             << " using " << session.ciphersuite().to_string() << std::endl;

   if(!session.session_id().empty())
      std::cout << "Session ID " << hex_encode(session.session_id()) << std::endl;

   if(!session.session_ticket().empty())
      std::cout << "Session ticket " << hex_encode(session.session_ticket()) << std::endl;

   return true;
   }

void dgram_socket_write(int sockfd, const byte buf[], size_t length)
   {
   ssize_t sent = ::send(sockfd, buf, length, MSG_NOSIGNAL);

   if(sent == -1)
      std::cout << "Error writing to socket - " << strerror(errno) << std::endl;
   else if(sent != static_cast<ssize_t>(length))
      std::cout << "Packet of length " << length << " truncated to " << sent << std::endl;
   }

void stream_socket_write(int sockfd, const byte buf[], size_t length)
   {
   while(length)
      {
      ssize_t sent = ::send(sockfd, buf, length, MSG_NOSIGNAL);

      if(sent == -1)
         {
         if(errno == EINTR)
            sent = 0;
         else
            throw std::runtime_error("Socket write failed");
         }

      buf += sent;
      length -= sent;
      }
   }

void alert_received(TLS::Alert alert, const byte[], size_t)
   {
   std::cout << "Alert: " << alert.type_string() << std::endl;
   }

int tls_server(int argc, char* argv[])
   {
   if(argc != 4 && argc != 5)
      {
      std::cout << "Usage: " << argv[0] << " server.crt server.key port [tcp|udp]" << std::endl;
      return 1;
      }

   const std::string server_crt = argv[1];
   const std::string server_key = argv[2];
   const int port = to_u32bit(argv[3]);
   const std::string transport = (argc >= 5) ? argv[4] : "tcp";

   const bool is_tcp = (transport == "tcp");

   try
      {
      AutoSeeded_RNG rng;

      TLS::Policy policy;

      TLS::Session_Manager_In_Memory session_manager(rng);

      Basic_Credentials_Manager creds(rng, server_crt, server_key);

      auto protocol_chooser = [](const std::vector<std::string>& protocols) -> std::string {
         for(size_t i = 0; i != protocols.size(); ++i)
            std::cout << "Client offered protocol " << i << " = " << protocols[i] << std::endl;
         return "echo/1.0"; // too bad
      };

      std::cout << "Listening for new connections on " << transport << " port " << port << std::endl;

      int server_fd = make_server_socket(is_tcp, port);

      while(true)
         {
         try
            {
            int fd;

            if(is_tcp)
               fd = ::accept(server_fd, nullptr, nullptr);
            else
               {
               struct sockaddr_in from;
               socklen_t from_len = sizeof(sockaddr_in);

               if(::recvfrom(server_fd, nullptr, 0, MSG_PEEK,
                             (struct sockaddr*)&from, &from_len) != 0)
                  throw std::runtime_error("Could not peek next packet");

               if(::connect(server_fd, (struct sockaddr*)&from, from_len) != 0)
                  throw std::runtime_error("Could not connect UDP socket");

               fd = server_fd;
               }

            std::cout << "New connection received" << std::endl;

            auto socket_write = is_tcp ? std::bind(stream_socket_write, fd, _1, _2) :
                                         std::bind(dgram_socket_write, fd, _1, _2);

            std::string s;
            std::list<std::string> pending_output;

            auto proc_fn = [&](const byte input[], size_t input_len)
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

            TLS::Server server(socket_write,
                               proc_fn,
                               alert_received,
                               handshake_complete,
                               session_manager,
                               creds,
                               policy,
                               rng,
                               protocol_chooser,
                               !is_tcp);

            while(!server.is_closed())
               {
               byte buf[4*1024] = { 0 };
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
                  std::string s = pending_output.front();
                  pending_output.pop_front();
                  server.send(s);

                  if(s == "quit\n")
                     server.close();
                  }
               }

            if(is_tcp)
               ::close(fd);

            }
         catch(std::exception& e)
            {
            std::cout << "Connection problem: " << e.what() << std::endl;
            return 1;
            }
         }
   }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }

   return 0;
   }

REGISTER_APP(tls_server);

}

#endif
