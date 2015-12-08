/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_BCRYPT)

#include <botan/bcrypt.h>

namespace {

int bcrypt(const std::vector<std::string> &args)
   {
   if(args.size() == 2)
      {
      AutoSeeded_RNG rng;

      const std::string password = args[1];

      std::cout << generate_bcrypt(password, rng, 12) << std::endl;
      return 0;
      }
   else if(args.size() == 3)
      {
      const std::string password = args[1];
      const std::string hash = args[2];

      if(hash.length() != 60)
         std::cout << "Note: bcrypt '" << hash << "' has wrong length and cannot be valid" << std::endl;

      const bool ok = check_bcrypt(password, hash);

      std::cout << "Password is " << (ok ? "valid" : "NOT valid") << std::endl;
      return (ok ? 0 : 1);
      }

   std::cout << "Usage: " << args[0] << " password\n"
             << "       " << args[0] << " password passhash" << std::endl;
   return 1;
   }

REGISTER_APP(bcrypt);

}

#endif
