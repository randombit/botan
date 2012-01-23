#include <botan/botan.h>
#include <botan/tls_server.h>
#include <botan/hex.h>

#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/x509self.h>
#include <botan/secqueue.h>

#include "socket.h"
#include "credentials.h"

using namespace Botan;

using namespace std::tr1::placeholders;

#include <stdio.h>
#include <string>
#include <iostream>
#include <memory>

bool handshake_complete(const TLS::Session& session)
   {
   printf("Handshake complete, protocol=%04X ciphersuite=%s compression=%d\n",
          session.version(), session.ciphersuite().to_string().c_str(),
          session.compression_method());

   printf("Session id = %s\n", hex_encode(session.session_id()).c_str());
   printf("Master secret = %s\n", hex_encode(session.master_secret()).c_str());
   return true;
   }

class Blocking_TLS_Server
   {
   public:
      Blocking_TLS_Server(std::tr1::function<void (const byte[], size_t)> output_fn,
                          std::tr1::function<size_t (byte[], size_t)> input_fn,
                          std::vector<std::string>& protocols,
                          TLS::Session_Manager& sessions,
                          Credentials_Manager& creds,
                          TLS::Policy& policy,
                          RandomNumberGenerator& rng) :
         input_fn(input_fn),
         server(
            output_fn,
            std::tr1::bind(&Blocking_TLS_Server::reader_fn, std::tr1::ref(*this), _1, _2, _3),
            handshake_complete,
            sessions,
            creds,
            policy,
            rng),
         exit(false)
         {
         read_loop();
         }

      size_t read(byte buf[], size_t buf_len)
         {
         size_t got = read_queue.read(buf, buf_len);

         while(!exit && !got)
            {
            read_loop(5); // header size
            got = read_queue.read(buf, buf_len);
            }

         return got;
         }

      void write(const byte buf[], size_t buf_len)
         {
         server.send(buf, buf_len);
         }

      void close() { server.close(); }

      bool is_active() const { return server.is_active(); }

      TLS::Server& underlying() { return server; }
   private:
      void read_loop(size_t init_desired = 0)
         {
         size_t desired = init_desired;

         byte buf[4096];
         while(!exit && (!server.is_active() || desired))
            {
            const size_t asking = std::max(sizeof(buf), std::min(desired, static_cast<size_t>(1)));

            const size_t socket_got = input_fn(&buf[0], asking);

            if(socket_got == 0) // eof?
               {
               close();
               printf("got eof on socket\n");
               exit = true;
               }

            desired = server.received_data(&buf[0], socket_got);
            }
         }

      void reader_fn(const byte buf[], size_t buf_len, u16bit alert_code)
         {
         if(buf_len == 0 && alert_code != TLS::NULL_ALERT)
            {
            printf("Alert: %d\n", alert_code);
            //exit = true;
            }

         printf("Got %d bytes: ", (int)buf_len);
         for(size_t i = 0; i != buf_len; ++i)
            {
            if(isprint(buf[i]))
               printf("%c", buf[i]);
            }
         printf("\n");

         read_queue.write(buf, buf_len);
         }

      std::tr1::function<size_t (byte[], size_t)> input_fn;
      TLS::Server server;
      SecureQueue read_queue;
      bool exit;
   };

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

      Server_Socket listener(port);

      TLS::Policy policy;

      TLS::Session_Manager_In_Memory sessions;

      Credentials_Manager_Simple creds(rng);

      std::vector<std::string> protocols;
      protocols.push_back("spdy/2");
      protocols.push_back("http/1.0");

      while(true)
         {
         try {
            printf("Listening for new connection on port %d\n", port);

            std::auto_ptr<Socket> sock(listener.accept());

            printf("Got new connection\n");

            Blocking_TLS_Server tls(
               std::tr1::bind(&Socket::write, std::tr1::ref(sock), _1, _2),
               std::tr1::bind(&Socket::read, std::tr1::ref(sock), _1, _2, true),
               protocols,
               sessions,
               creds,
               policy,
               rng);

            const char* msg = "Welcome to the best echo server evar\n";
            tls.write((const Botan::byte*)msg, strlen(msg));

            std::string line;

            while(tls.is_active())
               {
               byte b;
               size_t got = tls.read(&b, 1);

               if(got == 0)
                  break;

               line += (char)b;
               if(b == '\n')
                  {
                  //std::cout << line;

                  tls.write(reinterpret_cast<const byte*>(line.data()), line.size());

                  if(line == "quit\n")
                     {
                     tls.close();
                     break;
                     }

                  if(line == "reneg\n")
                     tls.underlying().renegotiate();

                  line.clear();
                  }
               }
            }
         catch(std::exception& e) { printf("Connection problem: %s\n", e.what()); }
         }
   }
   catch(std::exception& e)
      {
      printf("%s\n", e.what());
      return 1;
      }
   return 0;
   }
