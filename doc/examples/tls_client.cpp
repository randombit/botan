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

      Unix_Socket sock("randombit.net", 443);

      std::auto_ptr<Botan::RandomNumberGenerator> rng(
         Botan::RandomNumberGenerator::make_rng());

      TLS_Client tls(*rng, sock);

      printf("Connection open\n");

      while(true)
         {
         if(tls.is_closed())
            break;

         std::string str;
         std::getline(std::cin, str);
         str += "\n";
         tls.write((const byte*)str.c_str(), str.length());

         byte buf[4096] = { 0 };
         tls.read(buf, sizeof(buf));
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
