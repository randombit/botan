/*
   A simple template for Botan applications, showing startup, etc
*/
#include <botan/botan.h>
using namespace Botan;

/* This is how you can do compile-time version checking */
/*
#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,3,9)
  #error Your Botan installation is too old; upgrade to 1.3.9 or later
#endif
*/

#include <iostream>

int main()
   {
   try {
      /* Put it inside the try block so exceptions at startup/shutdown will
         get caught.
      */
      LibraryInitializer init;
   }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }
   return 0;
   }
