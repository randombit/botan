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

void proc_data(const byte data[], size_t data_len, u16bit alert_info)
   {
   printf("Block of data %d bytes alert %04X\n", (int)data_len, alert_info);
   for(size_t i = 0; i != data_len; ++i)
      printf("%c", data[i]);
   }

int main(int argc, char* argv[])
   {
   int port = 4433;

   if(argc == 2)
      port = to_u32bit(argv[1]);

   try
      {
      LibraryInitializer botan_init;
      //SocketInitializer socket_init;

      AutoSeeded_RNG rng;

      //RSA_PrivateKey key(rng, 1024);
      DSA_PrivateKey key(rng, DL_Group("dsa/jce/1024"));

      X509_Cert_Options options(
         "localhost/US/Syn Ack Labs/Mathematical Munitions Dept");

      X509_Certificate cert =
         X509::create_self_signed_cert(options, key, "SHA-1", rng);

      Server_Socket listener(port);

      Server_TLS_Policy policy;

      TLS_Session_Manager_In_Memory sessions;

      while(true)
         {
         try {
            printf("Listening for new connection on port %d\n", port);

            Socket* sock = listener.accept();

            printf("Got new connection\n");

            TLS_Server tls(
               std::tr1::bind(&Socket::write, std::tr1::ref(sock), _1, _2),
               proc_data,
               sessions,
               policy,
               rng,
               cert,
               key);

            SecureVector<byte> buf(1024);
            size_t desired = 0;
            while(!tls.is_active() || desired)
               {
               const size_t socket_got = sock->read(&buf[0], desired || 1);
               desired = tls.received_data(&buf[0], socket_got);
               }

            const std::string hostname = tls.server_name_indicator();

            if(hostname != "")
               printf("Client requested host '%s'\n", hostname.c_str());

            printf("Writing some text\n");

            char msg[] = "Welcome to the best echo server evar\n";
            tls.queue_for_sending((const Botan::byte*)msg, strlen(msg));

            while(true)
               {
               size_t got = sock->read(&buf[0], buf.size(), true);

               if(got == 0)
                  break;

               tls.received_data(&buf[0], got);
               }

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
