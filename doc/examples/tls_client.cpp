#include <botan/botan.h>
#include <botan/tls_client.h>
#include <stdio.h>
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

using namespace Botan;

class Client_TLS_Policy : public TLS_Policy
   {
   public:
      bool check_cert(const std::vector<X509_Certificate>& certs) const
         {
         for(size_t i = 0; i != certs.size(); ++i)
            {
            std::cout << certs[i].to_string();
            }

         std::cout << "Warning: not checking cert signatures\n";

         return true;
         }
   };

int connect_to_host(const std::string& host, u16bit port)
   {
   hostent* host_addr = ::gethostbyname(host.c_str());

   if(host_addr == 0)
      throw std::runtime_error("gethostbyname failed for " + host);

   if(host_addr->h_addrtype != AF_INET) // FIXME
      throw std::runtime_error(host + " has IPv6 address");

   int fd = ::socket(PF_INET, SOCK_STREAM, 0);
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

void socket_write(int sockfd, const byte buf[], size_t length)
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

   //printf("socket write %d\n", offset);
   }

void process_data(const byte buf[], size_t buf_size, u16bit alert_info)
   {
   if(alert_info != NULL_ALERT)
      {
      printf("Alert: %d\n", alert_info);
      }

   for(size_t i = 0; i != buf_size; ++i)
      printf("%c", buf[i]);
   }

int main(int argc, char* argv[])
   {
   if(argc != 2 && argc != 3)
      {
      printf("Usage: %s host [port]\n", argv[0]);
      return 1;
      }

   try
      {
      LibraryInitializer botan_init;
      AutoSeeded_RNG rng;
      Client_TLS_Policy policy;
      TLS_Session_Manager_In_Memory session_manager;

      std::string host = argv[1];
      u32bit port = argc == 3 ? Botan::to_u32bit(argv[2]) : 443;

      int sockfd = connect_to_host(host, port);

      TLS_Client client(std::tr1::bind(socket_write, sockfd, _1, _2),
                        process_data,
                        session_manager,
                        policy,
                        rng,
                        host);

      fd_set readfds;

      while(true)
         {
         FD_ZERO(&readfds);
         FD_SET(sockfd, &readfds);
         FD_SET(STDIN_FILENO, &readfds);

         ::select(sockfd + 1, &readfds, NULL, NULL, NULL);

         if(client.is_closed())
            break;

         if(FD_ISSET(sockfd, &readfds))
            {
            byte buf[1024] = { 0 };
            ssize_t got = read(sockfd, buf, sizeof(buf));

            if(got == 0)
               {
               printf("EOF on socket\n");
               break;
               }
            else if(got == -1)
               {
               printf("Socket error %d (%s)\n", errno, strerror(errno));
               continue;
               }

            //printf("socket read %d\n", got);

            client.received_data(buf, got);
            }
         else if(FD_ISSET(STDIN_FILENO, &readfds))
            {
            byte buf[1024] = { 0 };
            ssize_t got = read(STDIN_FILENO, buf, sizeof(buf));

            if(got == 0)
               {
               printf("EOF on stdin\n");
               client.close();
               break;
               }
            else if(got == -1)
               {
               printf("Error reading stdin %d (%s)\n", errno, strerror(errno));
               continue;
               }

            client.queue_for_sending(buf, got);
            }
         }
   }
   catch(std::exception& e)
      {
      printf("%s\n", e.what());
      return 1;
      }
   return 0;
   }
