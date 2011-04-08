/*
* Read an X.509 certificate, and print various things about it
* (C) 2003 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/botan.h>
#include <botan/x509cert.h>
using namespace Botan;

#include <iostream>

int main(int argc, char* argv[])
   {
   if(argc != 2)
      {
      std::cout << "Usage: " << argv[0] << " <x509cert>\n";
      return 1;
      }

   Botan::LibraryInitializer init;

   try {
      X509_Certificate cert(argv[1]);

      std::cout << cert.to_string();
   }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }
   return 0;
   }
