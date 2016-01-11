/*
* Message Authentication Code base class
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/mac.h>
#include <botan/internal/algo_registry.h>
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

std::unique_ptr<MessageAuthenticationCode> MessageAuthenticationCode::create(const std::string& algo_spec,
                                                                             const std::string& provider)
   {
   return std::unique_ptr<MessageAuthenticationCode>(make_a<MessageAuthenticationCode>(MessageAuthenticationCode::Spec(algo_spec), provider));
   }

std::vector<std::string> MessageAuthenticationCode::providers(const std::string& algo_spec)
   {
   return providers_of<MessageAuthenticationCode>(MessageAuthenticationCode::Spec(algo_spec));
   }

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
BOTAN_REGISTER_T_NOARGS(MessageAuthenticationCode, Poly1305);
#endif

#if defined(BOTAN_HAS_SIPHASH)
BOTAN_REGISTER_NAMED_T_2LEN(MessageAuthenticationCode, SipHash, "SipHash", "base", 2, 4);
#endif

#if defined(BOTAN_HAS_ANSI_X919_MAC)
BOTAN_REGISTER_NAMED_T(MessageAuthenticationCode, "X9.19-MAC", ANSI_X919_MAC, make_new_T<ANSI_X919_MAC>);
#endif

}
