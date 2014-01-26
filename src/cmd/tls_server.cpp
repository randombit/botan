#include "apps.h"
#include <botan/tls_server.h>
#include <botan/hex.h>

#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/x509self.h>
#include <botan/secqueue.h>

#include "credentials.h"

using namespace Botan;

using namespace std::placeholders;

#include <stdio.h>
#include <string>
#include <iostream>
#include <memory>
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

int make_server_socket(const std::string& transport, u16bit port)
   {
   int type = (transport == "tcp") ? SOCK_STREAM : SOCK_DGRAM;

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

   if(transport != "udp")
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
             << " using " << session.ciphersuite().to_string() << "\n";

   if(!session.session_id().empty())
      std::cout << "Session ID " << hex_encode(session.session_id()) << "\n";

   if(!session.session_ticket().empty())
      std::cout << "Session ticket " << hex_encode(session.session_ticket()) << "\n";

   return true;
   }

void dgram_socket_write(int sockfd, const byte buf[], size_t length)
   {
   ssize_t sent = ::send(sockfd, buf, length, MSG_NOSIGNAL);

   if(sent == -1)
      std::cout << "Error writing to socket - " << strerror(errno) << "\n";
   else if(sent != static_cast<ssize_t>(length))
      std::cout << "Packet of length " << length << " truncated to " << sent << "\n";
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

void alert_received(TLS::Alert alert, const byte buf[], size_t buf_size)
   {
   std::cout << "Alert: " << alert.type_string() << "\n";
   }

}

int tls_server_main(int argc, char* argv[])
   {
   int port = 4433;
   std::string transport = "tcp";

   if(argc >= 2)
      port = to_u32bit(argv[1]);
   if(argc >= 3)
      transport = argv[2];

   try
      {
      AutoSeeded_RNG rng;

      TLS::Policy policy;

      TLS::Session_Manager_In_Memory session_manager(rng);

      Credentials_Manager_Simple creds(rng);

      /*
      * These are the protocols we advertise to the client, but the
      * client will send back whatever it actually plans on talking,
      * which may or may not take into account what we advertise.
      */
      const std::vector<std::string> protocols = { "echo/1.0", "echo/1.1" };

      std::cout << "Listening for new connections on " << transport << " port " << port << "\n";

      int server_fd = make_server_socket(transport, port);

      while(true)
         {
         try
            {
            int fd;

            if(transport == "tcp")
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

            std::cout << "New connection received\n";

            auto socket_write =
               (transport == "tcp") ?
               std::bind(stream_socket_write, fd, _1, _2) :
               std::bind(dgram_socket_write, fd, _1, _2);

            std::string s;
            std::list<std::string> pending_output;

            pending_output.push_back("Welcome to the best echo server evar\n");

            auto proc_fn = [&](const byte input[], size_t input_len)
               {
               for(size_t i = 0; i != input_len; ++i)
                  {
                  char c = (char)input[i];
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
                               protocols);

            while(!server.is_closed())
               {
               byte buf[4*1024] = { 0 };
               ssize_t got = ::read(fd, buf, sizeof(buf));

               if(got == -1)
                  {
                  std::cout << "Error in socket read - " << strerror(errno) << "\n";
                  break;
                  }

               if(got == 0)
                  {
                  std::cout << "EOF on socket\n";
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

            if(transport == "tcp")
               ::close(fd);

            }
         catch(std::exception& e)
            {
            std::cout << "Connection problem: " << e.what() << "\n";
            return 1;
            }
         }
   }
   catch(std::exception& e)
      {
      std::cout << e.what() << "\n";
      return 1;
      }

   return 0;
   }
