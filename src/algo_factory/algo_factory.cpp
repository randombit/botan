/*
Algorithm Factory
(C) 2008 Jack Lloyd
*/

#include <botan/algo_factory.h>
#include <botan/stl_util.h>
#include <botan/engine.h>
#include <botan/exceptn.h>

#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/hash.h>
#include <botan/mac.h>

#include <algorithm>

namespace Botan {

/**
* Setup caches
*/
Algorithm_Factory::Algorithm_Factory(Mutex_Factory& mf) :
   block_cipher_cache(mf.make()),
   stream_cipher_cache(mf.make()),
   hash_cache(mf.make()),
   mac_cache(mf.make())
   {
   }

/**
* Delete all engines
*/
Algorithm_Factory::~Algorithm_Factory()
   {
   std::for_each(engines.begin(), engines.end(), del_fun<Engine>());
   engines.clear();
   }

/**
* Add a new engine to the search list
*/
void Algorithm_Factory::add_engine(Engine* engine)
   {
   engines.push_back(engine);
   }

/*************************************************
* Get an engine out of the list                  *
*************************************************/
Engine* Algorithm_Factory::get_engine_n(u32bit n) const
   {
   if(n >= engines.size())
      return 0;
   return engines[n];
   }

/**
* Return the possible providers of a request
*/
std::vector<std::string>
Algorithm_Factory::providers_of(const std::string& algo_name)
   {
   if(prototype_block_cipher(algo_name))
      return block_cipher_cache.providers_of(algo_name);

   if(prototype_stream_cipher(algo_name))
      return stream_cipher_cache.providers_of(algo_name);

   if(prototype_hash_function(algo_name))
      return hash_cache.providers_of(algo_name);

   if(prototype_mac(algo_name))
      return mac_cache.providers_of(algo_name);

   return std::vector<std::string>();
   }

/**
* Return the prototypical block cipher cooresponding to this request
*/
const BlockCipher*
Algorithm_Factory::prototype_block_cipher(const SCAN_Name& request)
   {
   if(const BlockCipher* cache_hit = block_cipher_cache.get(request))
      return cache_hit;

   for(u32bit i = 0; i != engines.size(); ++i)
      {
      const std::string provider = engines[i]->provider_name();

      SCAN_Name request_i(request.as_string(), provider);

      if(BlockCipher* impl = engines[i]->find_block_cipher(request_i, *this))
         block_cipher_cache.add(impl, request.as_string(), provider);
      }

   return block_cipher_cache.get(request);
   }

/**
* Return a new block cipher cooresponding to this request
*/
BlockCipher* Algorithm_Factory::make_block_cipher(const SCAN_Name& request)
   {
   if(const BlockCipher* prototype = prototype_block_cipher(request))
      return prototype->clone();
   throw Algorithm_Not_Found(request.as_string());
   }

/**
* Add a new block cipher
*/
void Algorithm_Factory::add_block_cipher(BlockCipher* block_cipher,
                                         const std::string& provider)
   {
   block_cipher_cache.add(block_cipher, block_cipher->name(), provider);
   }

/**
* Return the prototypical stream cipher cooresponding to this request
*/
const StreamCipher*
Algorithm_Factory::prototype_stream_cipher(const SCAN_Name& request)
   {
   if(const StreamCipher* cache_hit = stream_cipher_cache.get(request))
      return cache_hit;

   for(u32bit i = 0; i != engines.size(); ++i)
      {
      const std::string provider = engines[i]->provider_name();

      SCAN_Name request_i(request.as_string(), provider);

      if(StreamCipher* impl = engines[i]->find_stream_cipher(request_i, *this))
         stream_cipher_cache.add(impl, request.as_string(), provider);
      }

   return stream_cipher_cache.get(request);
   }

/**
* Return a new stream cipher cooresponding to this request
*/
StreamCipher* Algorithm_Factory::make_stream_cipher(const SCAN_Name& request)
   {
   if(const StreamCipher* prototype = prototype_stream_cipher(request))
      return prototype->clone();
   throw Algorithm_Not_Found(request.as_string());
   }

/**
* Add a new stream cipher
*/
void Algorithm_Factory::add_stream_cipher(StreamCipher* stream_cipher,
                                         const std::string& provider)
   {
   stream_cipher_cache.add(stream_cipher, stream_cipher->name(), provider);
   }

/**
* Return the prototypical object cooresponding to this request (if found)
*/
const HashFunction*
Algorithm_Factory::prototype_hash_function(const SCAN_Name& request)
   {
   if(const HashFunction* cache_hit = hash_cache.get(request))
      return cache_hit;

   for(u32bit i = 0; i != engines.size(); ++i)
      {
      const std::string provider = engines[i]->provider_name();

      SCAN_Name request_i(request.as_string(), provider);

      if(HashFunction* impl = engines[i]->find_hash(request_i, *this))
         hash_cache.add(impl, request.as_string(), provider);
      }

   return hash_cache.get(request);
   }

/**
* Return a new object cooresponding to this request
*/
HashFunction* Algorithm_Factory::make_hash_function(const SCAN_Name& request)
   {
   if(const HashFunction* prototype = prototype_hash_function(request))
      return prototype->clone();
   throw Algorithm_Not_Found(request.as_string());
   }

/**
* Add a new hash
*/
void Algorithm_Factory::add_hash_function(HashFunction* hash,
                                          const std::string& provider)
   {
   hash_cache.add(hash, hash->name(), provider);
   }

/**
* Return the prototypical object cooresponding to this request
*/
const MessageAuthenticationCode*
Algorithm_Factory::prototype_mac(const SCAN_Name& request)
   {
   if(const MessageAuthenticationCode* cache_hit = mac_cache.get(request))
      return cache_hit;

   for(u32bit i = 0; i != engines.size(); ++i)
      {
      const std::string provider = engines[i]->provider_name();

      SCAN_Name request_i(request.as_string(), provider);

      if(MessageAuthenticationCode* impl =
            engines[i]->find_mac(request_i, *this))
         mac_cache.add(impl, request.as_string(), provider);
      }

   return mac_cache.get(request);
   }

/**
* Return a new object cooresponding to this request
*/
MessageAuthenticationCode*
Algorithm_Factory::make_mac(const SCAN_Name& request)
   {
   if(const MessageAuthenticationCode* prototype = prototype_mac(request))
      return prototype->clone();
   throw Algorithm_Not_Found(request.as_string());
   }

/**
* Add a new mac
*/
void Algorithm_Factory::add_mac(MessageAuthenticationCode* mac,
                                const std::string& provider)
   {
   mac_cache.add(mac, mac->name(), provider);
   }

}
