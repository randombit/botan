/*
* EME Base Class
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/eme.h>
#include <botan/scan_name.h>

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

EME* get_eme(const std::string& algo_spec)
   {
   SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_EME_OAEP)
   if(req.algo_name() == "OAEP" && req.arg_count_between(1, 2))
      {
      if(req.arg_count() == 1 ||
         (req.arg_count() == 2 && req.arg(1) == "MGF1"))
         {
         if(auto hash = HashFunction::create(req.arg(0)))
            return new OAEP(hash.release());
         }
      }
#endif

#if defined(BOTAN_HAS_EME_PKCS1v15)
   if(req.algo_name() == "PKCS1v15" && req.arg_count() == 0)
      return new EME_PKCS1v15;
#endif

#if defined(BOTAN_HAS_EME_RAW)
   if(req.algo_name() == "Raw" && req.arg_count() == 0)
      return new EME_Raw;
#endif

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
