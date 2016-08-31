/*
* (C) 2016 Daniel Neus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_pkcs11.h"

namespace Botan_Tests {
	
#if defined(BOTAN_HAS_PKCS11)

using namespace Botan;
using namespace PKCS11;

std::vector<Test::Result> PKCS11_Test::run_pkcs11_tests(const std::string& name,
      std::vector<std::function<Test::Result()>>& fns)
   {
   std::vector<Test::Result> results;

   for(size_t i = 0; i != fns.size(); ++i)
      {
      try
         {
         results.push_back(fns[ i ]());
         }
      catch(PKCS11_ReturnError& e)
         {
         results.push_back(Test::Result::Failure(name + " test " + std::to_string(i), e.what()));

         if(e.get_return_value() == ReturnValue::PinIncorrect)
            {
            break; // Do not continue to not potentially lock the token
            }
         }
      catch(std::exception& e)
         {
         results.push_back(Test::Result::Failure(name + " test " + std::to_string(i), e.what()));
         }
      }

   return results;
   }

#endif

}
