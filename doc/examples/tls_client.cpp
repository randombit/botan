#include <botan/botan.h>
#include <botan/tls_client.h>
#include <botan/pkcs8.h>
#include <botan/hex.h>
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

#include "credentials.h"

using namespace Botan;

using namespace std::tr1::placeholders;

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

bool handshake_complete(const TLS::Session& session)
   {
   std::cout << "Handshake complete!\n";
   std::cout << "Protocol version " << session.version().to_string() << "\n";
   std::cout << "Ciphersuite " << std::hex << session.ciphersuite().to_string() << "\n";
   std::cout << "Session ID " << hex_encode(session.session_id()) << "\n";

   return true;
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
   }

bool got_alert = false;

void process_data(const byte buf[], size_t buf_size, u16bit alert_info)
   {
   if(alert_info != TLS::NULL_ALERT)
      {
      std::cout << "Alert: " << alert_info << "\n";
      got_alert = true;
      }

   for(size_t i = 0; i != buf_size; ++i)
      {
      std::cout << buf[i];
      }
   }

std::string protocol_chooser(const std::vector<std::string>& protocols)
   {
   for(size_t i = 0; i != protocols.size(); ++i)
      std::cout << "Protocol " << i << " = " << protocols[i] << "\n";
   return "http/1.1";
   }

void doit(RandomNumberGenerator& rng,
          TLS::Policy& policy,
          TLS::Session_Manager& session_manager,
          Credentials_Manager& creds,
          const std::string& host,
          u16bit port)
   {
   int sockfd = connect_to_host(host, port);

   TLS::Client client(std::tr1::bind(socket_write, sockfd, _1, _2),
                     process_data,
                     handshake_complete,
                     session_manager,
                     creds,
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
         byte buf[64] = { 0 };

         size_t to_read = rand() % sizeof(buf);
         if(to_read == 0)
            to_read = 1;

         ssize_t got = read(sockfd, buf, to_read);

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

         const size_t needed = client.received_data(buf, got);
         //std::cout << "Socket - got " << got << " bytes, need " << needed << "\n";
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

         client.send(buf, got);
         }
      }

   ::close(sockfd);
   }

int main(int argc, char* argv[])
   {
   if(argc != 2 && argc != 3)
      {
      std::cout << "Usage " << argv[0] << " host [port]\n";
      return 1;
      }

   try
      {
      LibraryInitializer botan_init;
      AutoSeeded_RNG rng;
      TLS::Policy policy;
      TLS::Session_Manager_In_Memory session_manager;

      Credentials_Manager_Simple creds(rng);

      std::string host = argv[1];
      u32bit port = argc == 3 ? Botan::to_u32bit(argv[2]) : 443;

      //while(true)
         doit(rng, policy, session_manager, creds, host, port);

   }
   catch(std::exception& e)
      {
      std::cout << "Exception: " << e.what() << "\n";
      return 1;
      }
   return 0;
   }
