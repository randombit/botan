/*
* EME Base Class
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/eme.h>
#include <botan/internal/algo_registry.h>

#if defined(BOTAN_HAS_EME_OAEP)
#include <botan/oaep.h>
#endif

#if defined(BOTAN_HAS_EME_PKCS1v15)
#include <botan/eme_pkcs.h>
#endif

#if defined(BOTAN_HAS_EME_RAW)
#include <botan/eme_raw.h>
#endif

namespace Botan {

#define BOTAN_REGISTER_EME(name, maker) BOTAN_REGISTER_T(EME, name, maker)
#define BOTAN_REGISTER_EME_NOARGS(name) BOTAN_REGISTER_T_NOARGS(EME, name)

#define BOTAN_REGISTER_EME_NAMED_NOARGS(type, name) \
   BOTAN_REGISTER_NAMED_T(EME, name, type, make_new_T<type>)

#if defined(BOTAN_HAS_EME_OAEP)
BOTAN_REGISTER_NAMED_T(EME, "OAEP", OAEP, OAEP::make);
#endif

#if defined(BOTAN_HAS_EME_PKCS1v15)
BOTAN_REGISTER_EME_NAMED_NOARGS(EME_PKCS1v15, "PKCS1v15");
#endif

#if defined(BOTAN_HAS_EME_RAW)
BOTAN_REGISTER_EME_NAMED_NOARGS(EME_Raw, "Raw");
#endif

EME* get_eme(const std::string& algo_spec)
   {
   SCAN_Name request(algo_spec);

   if(EME* eme = make_a<EME>(Botan::EME::Spec(algo_spec)))
      return eme;

   if(request.algo_name() == "Raw")
      return nullptr; // No padding

   throw Algorithm_Not_Found(algo_spec);
   }

/*
* Encode a message
*/
secure_vector<byte> EME::encode(const byte msg[], size_t msg_len,
                                size_t key_bits,
                                RandomNumberGenerator& rng) const
   {
   return pad(msg, msg_len, key_bits, rng);
   }

/*
* Encode a message
*/
secure_vector<byte> EME::encode(const secure_vector<byte>& msg,
                                size_t key_bits,
                                RandomNumberGenerator& rng) const
   {
   return pad(msg.data(), msg.size(), key_bits, rng);
   }


}
