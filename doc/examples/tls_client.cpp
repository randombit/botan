#include <botan/botan.h>
#include <botan/tls_client.h>
#include "socket.h"

using namespace Botan;

#include <stdio.h>
#include <string>
#include <iostream>
#include <memory>

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

      std::string host = argv[1];
      u32bit port = argc == 3 ? Botan::to_u32bit(argv[2]) : 443;

      printf("Connecting to %s:%d...\n", host.c_str(), port);

      SocketInitializer socket_init;

      Socket sock(argv[1], port);

      AutoSeeded_RNG rng;

      Client_TLS_Policy policy;

      TLS_Client tls(std::tr1::bind(&Socket::read, std::tr1::ref(sock), _1, _2),
                     std::tr1::bind(&Socket::write, std::tr1::ref(sock), _1, _2),
                     policy, rng);

      printf("Handshake extablished...\n");

#if 0
      std::string http_command = "GET / HTTP/1.1\r\n"
                                 "Server: " + host + ':' + to_string(port) + "\r\n\r\n";
#else
      std::string http_command = "GET / HTTP/1.0\r\n\r\n";
#endif

      tls.write((const Botan::byte*)http_command.c_str(),
                http_command.length());

      size_t total_got = 0;

      while(true)
         {
         if(tls.is_closed())
            break;

         Botan::byte buf[128+1] = { 0 };
         size_t got = tls.read(buf, sizeof(buf)-1);
         printf("%s", buf);
         fflush(0);

         total_got += got;
         }

      printf("\nRetrieved %d bytes total\n", total_got);
   }
   catch(std::exception& e)
      {
      printf("%s\n", e.what());
      return 1;
      }
   return 0;
   }
