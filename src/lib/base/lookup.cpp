/*
* Algorithm Retrieval
* (C) 1999-2007,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/lookup.h>
#include <botan/internal/algo_registry.h>
#include <botan/cipher_mode.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/pbkdf.h>

namespace Botan {

Transform* get_transform(const std::string& specstr,
                         const std::string& provider,
                         const std::string& dirstr)
   {
   Algo_Registry<Transform>::Spec spec(specstr, dirstr);
   return Algo_Registry<Transform>::global_registry().make(spec, provider);
   }

BlockCipher* get_block_cipher(const std::string& algo_spec, const std::string& provider)
   {
   return make_a<BlockCipher>(algo_spec, provider);
   }

StreamCipher* get_stream_cipher(const std::string& algo_spec, const std::string& provider)
   {
   return make_a<StreamCipher>(algo_spec, provider);
   }

HashFunction* get_hash_function(const std::string& algo_spec, const std::string& provider)
   {
   return make_a<HashFunction>(algo_spec, provider);
   }

MessageAuthenticationCode* get_mac(const std::string& algo_spec, const std::string& provider)
   {
   return make_a<MessageAuthenticationCode>(algo_spec, provider);
   }

std::vector<std::string> get_block_cipher_providers(const std::string& algo_spec)
   {
   return providers_of<BlockCipher>(BlockCipher::Spec(algo_spec));
   }

std::vector<std::string> get_stream_cipher_providers(const std::string& algo_spec)
   {
   return providers_of<StreamCipher>(StreamCipher::Spec(algo_spec));
   }

std::vector<std::string> get_hash_function_providers(const std::string& algo_spec)
   {
   return providers_of<HashFunction>(HashFunction::Spec(algo_spec));
   }

std::vector<std::string> get_mac_providers(const std::string& algo_spec)
   {
   return providers_of<MessageAuthenticationCode>(MessageAuthenticationCode::Spec(algo_spec));
   }

/*
* Get a PBKDF algorithm by name
*/
PBKDF* get_pbkdf(const std::string& algo_spec, const std::string& provider)
   {
   if(PBKDF* pbkdf = make_a<PBKDF>(algo_spec, provider))
      return pbkdf;
   throw Algorithm_Not_Found(algo_spec);
   }

}
