/*
* Message Authentication Code base class
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/mac.h>
#include <botan/mem_ops.h>

namespace Botan {

/*
* Default (deterministic) MAC verification operation
*/
bool MessageAuthenticationCode::verify_mac(const byte mac[], size_t length)
   {
   SecureVector<byte> our_mac = final();

   if(our_mac.size() != length)
      return false;

   return same_mem(&our_mac[0], &mac[0], length);
   }

}
