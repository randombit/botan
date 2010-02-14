/*
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/init.h>
#include <botan/tls_client.h>
#include <botan/unx_sock.h>

using namespace Botan;

#include <stdio.h>
#include <string>
#include <iostream>
#include <memory>

int main()
   {
   try
      {
      LibraryInitializer init;

      Unix_Socket sock("www.randombit.net", 443);

      std::auto_ptr<Botan::RandomNumberGenerator> rng(
         Botan::RandomNumberGenerator::make_rng());

      TLS_Client tls(*rng, sock);

      std::string http_command = "GET /bitbashing\r\n";
      tls.write((const byte*)http_command.c_str(), http_command.length());

      while(true)
         {
         if(tls.is_closed())
            break;

         byte buf[16+1] = { 0 };
         u32bit got = tls.read(buf, sizeof(buf)-1);
         printf("%s", buf);
         fflush(0);
         }
   }
   catch(std::exception& e)
      {
      printf("%s\n", e.what());
      return 1;
      }
   return 0;
   }
