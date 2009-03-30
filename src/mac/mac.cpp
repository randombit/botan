/**
Message Authentication Code base class
(C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/mac.h>

namespace Botan {

/**
* Default (deterministic) MAC verification operation
*/
bool MessageAuthenticationCode::verify_mac(const byte mac[], u32bit length)
   {
   SecureVector<byte> our_mac = final();
   if(our_mac.size() != length)
      return false;
   for(u32bit j = 0; j != length; ++j)
      if(mac[j] != our_mac[j])
         return false;
   return true;
   }

}
