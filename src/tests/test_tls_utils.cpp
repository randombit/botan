/*
* (C) 1999-2021 Jack Lloyd
* (C) 2021      René Meusel, Hannes Rantzsch
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_tls_utils.h"

#if defined(BOTAN_HAS_TLS)

#include "tests.h"

#include <fstream>

namespace Botan_Tests {

Botan::TLS::Text_Policy read_tls_policy(const std::string& policy_file)
   {
   const std::string fspath = Test::data_file("tls-policy/" + policy_file + ".txt");
  
   std::ifstream is(fspath.c_str());
   if(!is.good())
      {
      throw Test_Error("Missing policy file " + fspath);
      }
  
   return Botan::TLS::Text_Policy(is);
   }
}

#endif
