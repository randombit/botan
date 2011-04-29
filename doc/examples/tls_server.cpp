#include <botan/botan.h>
#include <botan/tls_server.h>

#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/x509self.h>

#include "socket.h"

using namespace Botan;

#include <stdio.h>
#include <string>
#include <iostream>
#include <memory>

class Server_TLS_Policy : public TLS_Policy
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
   int port = 4433;

   if(argc == 2)
      port = to_u32bit(argv[1]);

   try
      {
      LibraryInitializer botan_init;
      SocketInitializer socket_init;

      AutoSeeded_RNG rng;

      //RSA_PrivateKey key(rng, 1024);
      DSA_PrivateKey key(rng, DL_Group("dsa/jce/1024"));

      X509_Cert_Options options(
         "localhost/US/Syn Ack Labs/Mathematical Munitions Dept");

      X509_Certificate cert =
         X509::create_self_signed_cert(options, key, "SHA-1", rng);

      Server_Socket listener(port);

      Server_TLS_Policy policy;

      while(true)
         {
         try {
            printf("Listening for new connection on port %d\n", port);

            Socket* sock = listener.accept();

            printf("Got new connection\n");

            TLS_Server tls(
              std::tr1::bind(&Socket::read, std::tr1::ref(sock), _1, _2),
              std::tr1::bind(&Socket::write, std::tr1::ref(sock), _1, _2),
              policy,
              rng,
              cert,
              key);

            std::string hostname = tls.requested_hostname();

            if(hostname != "")
               printf("Client requested host '%s'\n", hostname.c_str());

            printf("Writing some text\n");

            char msg[] = "Foo\nBar\nBaz\nQuux\n";
            tls.write((const Botan::byte*)msg, strlen(msg));

            printf("Now trying a read...\n");

            char buf[1024] = { 0 };
            u32bit got = tls.read((Botan::byte*)buf, sizeof(buf)-1);
            printf("%d: '%s'\n", got, buf);

            tls.close();
            }
         catch(std::exception& e) { printf("%s\n", e.what()); }
         }
   }
   catch(std::exception& e)
      {
      printf("%s\n", e.what());
      return 1;
      }
   return 0;
   }
