/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/botan.h>
#include <botan/passhash.h>
#include <iostream>
#include <memory>

#include <stdio.h>

int main(int argc, char* argv[])
   {
   if(argc != 2 && argc != 3)
      {
      std::cerr << "Usage: " << argv[0] << " password\n";
      std::cerr << "Usage: " << argv[0] << " password hash\n";
      return 1;
      }

   Botan::LibraryInitializer init;

   try
      {

      if(argc == 2)
         {
         Botan::AutoSeeded_RNG rng;

         Botan::u32bit work_factor = 10;

         std::cout << "H('" << argv[1] << "') = "
                   << Botan::password_hash(argv[1], rng, work_factor) << '\n';
         }
      else
         {
         bool ok = Botan::password_hash_ok(argv[1], argv[2]);
         if(ok)
            std::cout << "Password and hash match\n";
         else
            std::cout << "Password and hash do not match\n";
         }
      }
   catch(std::exception& e)
      {
      std::cerr << e.what() << '\n';
      return 1;
      }
   return 0;
   }
