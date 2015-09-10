/*
* Message Authentication Code base class
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/mac.h>
#include <botan/internal/mac_utils.h>
#include <botan/mem_ops.h>

#if defined(BOTAN_HAS_CBC_MAC)
  #include <botan/cbc_mac.h>
#endif

#if defined(BOTAN_HAS_CMAC)
  #include <botan/cmac.h>
#endif

#if defined(BOTAN_HAS_HMAC)
  #include <botan/hmac.h>
#endif

#if defined(BOTAN_HAS_POLY1305)
  #include <botan/poly1305.h>
#endif

#if defined(BOTAN_HAS_SIPHASH)
  #include <botan/siphash.h>
#endif

#if defined(BOTAN_HAS_ANSI_X919_MAC)
  #include <botan/x919_mac.h>
#endif

namespace Botan {

MessageAuthenticationCode::~MessageAuthenticationCode() {}

/*
* Default (deterministic) MAC verification operation
*/
bool MessageAuthenticationCode::verify_mac(const byte mac[], size_t length)
   {
   secure_vector<byte> our_mac = final();

   if(our_mac.size() != length)
      return false;

   return same_mem(our_mac.data(), mac, length);
   }


#if defined(BOTAN_HAS_CBC_MAC)
BOTAN_REGISTER_NAMED_T(MessageAuthenticationCode, "CBC-MAC", CBC_MAC, CBC_MAC::make);
#endif

#if defined(BOTAN_HAS_CMAC)
BOTAN_REGISTER_NAMED_T(MessageAuthenticationCode, "CMAC", CMAC, CMAC::make);
#endif

#if defined(BOTAN_HAS_HMAC)
BOTAN_REGISTER_NAMED_T(MessageAuthenticationCode, "HMAC", HMAC, HMAC::make);
#endif

#if defined(BOTAN_HAS_POLY1305)
BOTAN_REGISTER_MAC_NOARGS(Poly1305);
#endif

#if defined(BOTAN_HAS_SIPHASH)
BOTAN_REGISTER_NAMED_T_2LEN(MessageAuthenticationCode, SipHash, "SipHash", "base", 2, 4);
#endif

#if defined(BOTAN_HAS_ANSI_X919_MAC)
BOTAN_REGISTER_MAC_NAMED_NOARGS(ANSI_X919_MAC, "X9.19-MAC");
#endif

}
