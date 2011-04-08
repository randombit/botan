#include <botan/botan.h>
#include <botan/bcrypt.h>
#include <iostream>

using namespace Botan;

int main(int argc, char* argv[])
   {
   if(argc != 2 && argc != 3)
     {
     std::cout << "Usage: " << argv[0] << " password\n"
               << "       " << argv[0] << " password passhash\n";
     return 1;
     }

   LibraryInitializer init;

   if(argc == 2)
      {
      AutoSeeded_RNG rng;

      std::cout << generate_bcrypt(argv[1], rng, 12) << "\n";
      }
   else if(argc == 3)
      {
      if(strlen(argv[2]) != 60)
         {
         std::cout << "Note: hash " << argv[2]
                   << " has wrong length and cannot be valid\n";
         }

      const bool ok = check_bcrypt(argv[1], argv[2]);

      std::cout << "Password is " << (ok ? "valid" : "NOT valid") << "\n";
      }

   return 0;
   }
