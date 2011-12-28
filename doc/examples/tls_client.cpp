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

class HTTPS_Client
   {
   public:
      HTTPS_Client(const std::string& host, u16bit port, RandomNumberGenerator& r) :
         rng(r),
         socket(host, port),
         client(std::tr1::bind(&HTTPS_Client::socket_write, std::tr1::ref(*this), _1, _2),
                std::tr1::bind(&HTTPS_Client::proc_data, std::tr1::ref(*this), _1, _2, _3),
                sessions,
                policy,
                rng)
         {
         SecureVector<byte> socket_buf(1024);
         size_t desired = 0;

         quit_reading = false;

         while(!client.is_active() || desired)
            {
            const size_t socket_got = socket.read(&socket_buf[0], socket_buf.size());
            //printf("Got %d bytes from socket\n", socket_got);
            desired = client.received_data(&socket_buf[0], socket_got);
            socket_buf.resize(desired || 1);
            //printf("Going around for another read?\n");

            if(quit_reading)
               break;
            }
         }

      void socket_write(const byte buf[], size_t buf_size)
         {
         std::cout << "socket_write " << buf_size << "\n";
         socket.write(buf, buf_size);
         }

      void proc_data(const byte data[], size_t data_len, u16bit alert_info)
         {
         printf("Block of data %d bytes alert %d\n", (int)data_len, alert_info);
         for(size_t i = 0; i != data_len; ++i)
            printf("%c", data[i]);

         if(alert_info != 255)
            quit_reading = true;
         }

      void write(const std::string& s)
         {
         client.queue_for_sending((const byte*)s.c_str(), s.length());
         }

      void read_response()
         {
         while(!quit_reading)
            {
            SecureVector<byte> buf(4096);

            size_t got = socket.read(&buf[0], buf.size(), true);

            if(got == 0)
               break;

            client.received_data(&buf[0], got);
            }
         }

   private:
      bool quit_reading;
      RandomNumberGenerator& rng;
      Socket socket;
      Client_TLS_Policy policy;
      TLS_Session_Manager_In_Memory sessions;

      TLS_Client client;
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

      //SocketInitializer socket_init;

      AutoSeeded_RNG rng;

      printf("Connecting to %s:%d...\n", host.c_str(), port);

      HTTPS_Client https(host, port, rng);

      std::string http_command = "GET / HTTP/1.0\r\n\r\n";

      printf("Sending request\n");
      https.write(http_command);

      https.read_response();

   }
   catch(std::exception& e)
      {
      printf("%s\n", e.what());
      return 1;
      }
   return 0;
   }
