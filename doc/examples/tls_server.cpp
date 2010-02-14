/*
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/init.h>
#include <botan/tls_server.h>
#include <botan/unx_sock.h>

#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/x509self.h>

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

      std::auto_ptr<RandomNumberGenerator> rng(
         RandomNumberGenerator::make_rng());

      RSA_PrivateKey key(*rng, 512);
      //DSA_PrivateKey key(get_dl_group("DSA-1024"));

      X509_Cert_Options options(
         "www.randombit.net/US/Syn Ack Labs/Mathematical Munitions Dept");

      X509_Certificate cert =
         X509::create_self_signed_cert(options, key, "SHA-1", *rng);

      Unix_Server_Socket listener(4434);

      printf("Now listening...\n");

      while(true)
         {
         try {
            Socket* sock = listener.accept();

            printf("Got new connection\n");

            TLS_Server tls(*rng, *sock, cert, key);

            char msg[] = "Foo\nBar\nBaz\nQuux\n";
            tls.write((const byte*)msg, strlen(msg));

            char buf[10] = { 0 };
            u32bit got = tls.read((byte*)buf, 9);
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
