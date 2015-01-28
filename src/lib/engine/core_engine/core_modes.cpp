/*
* Core Engine
* (C) 1999-2007,2011,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/core_engine.h>
#include <botan/parsing.h>
#include <botan/filters.h>
#include <botan/algo_factory.h>
#include <botan/mode_pad.h>
#include <botan/transform_filter.h>
#include <botan/cipher_mode.h>

#if defined(BOTAN_HAS_OFB)
  #include <botan/ofb.h>
#endif

#if defined(BOTAN_HAS_CTR_BE)
  #include <botan/ctr.h>
#endif

namespace Botan {

/*
* Get a cipher object
*/
Keyed_Filter* Core_Engine::get_cipher(const std::string& algo_spec,
                                      Cipher_Dir direction,
                                      Algorithm_Factory& af)
   {
   std::vector<std::string> algo_parts = split_on(algo_spec, '/');
   if(algo_parts.empty())
      throw Invalid_Algorithm_Name(algo_spec);

   const std::string cipher_name = algo_parts[0];

   // check if it is a stream cipher first (easy case)
   const StreamCipher* stream_cipher = af.prototype_stream_cipher(cipher_name);
   if(stream_cipher)
      return new StreamCipher_Filter(stream_cipher->clone());

   const BlockCipher* block_cipher = af.prototype_block_cipher(cipher_name);
   if(!block_cipher)
      return nullptr;

   if(algo_parts.size() >= 4)
      return nullptr; // 4 part mode, not something we know about

   if(algo_parts.size() < 2)
      throw Lookup_Error("Cipher specification '" + algo_spec +
                         "' is missing mode identifier");

   const std::string mode = algo_parts[1];

#if defined(BOTAN_HAS_OFB)
   if(mode == "OFB")
      return new StreamCipher_Filter(new OFB(block_cipher->clone()));
#endif

#if defined(BOTAN_HAS_CTR_BE)
   if(mode == "CTR-BE")
      return new StreamCipher_Filter(new CTR_BE(block_cipher->clone()));
#endif

   std::unique_ptr<Cipher_Mode> c(get_cipher_mode(algo_spec, direction));
   if(c)
      return new Transform_Filter(c.release());

   throw Algorithm_Not_Found(algo_spec);
   }

}
