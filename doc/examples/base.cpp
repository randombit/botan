/*
   A simple template for Botan applications, showing startup, etc
*/
#include <botan/botan.h>
using namespace Botan;

/* This is how you can do compile-time version checking */

#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,6,3)
  #error Your Botan installation is too old; upgrade to 1.6.3 or later
#endif

#include <iostream>

int main(int argc, char* argv[])
   {
   Botan::LibraryInitializer init;

   try
      {
      /* Put it inside the try block so exceptions at startup/shutdown will
         get caught.

         It will be initialized with default options
      */

      if(argc > 2)
         {
         std::cout << "Usage: " << argv[0] << "[initializer args]\n";
         return 2;
         }

      std::string args = (argc == 2) ? argv[1] : "";

      LibraryInitializer init(args);
      // your operations here
   }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }
   return 0;
   }
