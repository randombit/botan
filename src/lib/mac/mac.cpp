/*
* Message Authentication Code base class
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/mac.h>
#include <botan/mem_ops.h>

namespace Botan {

/*
* Default (deterministic) MAC verification operation
*/
bool MessageAuthenticationCode::verify_mac(const byte mac[], size_t length)
   {
   secure_vector<byte> our_mac = final();

   if(our_mac.size() != length)
      return false;

   return same_mem(our_mac.data(), &mac[0], length);
   }

}
