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
   engines.insert(engines.begin(), engine);
   }

/**
* Set the preferred provider for an algorithm
*/
void Algorithm_Factory::set_preferred_provider(const std::string& algo_spec,
                                               const std::string& provider)
   {
   if(prototype_block_cipher(algo_spec))
      block_cipher_cache.set_preferred_provider(algo_spec, provider);
   else if(prototype_stream_cipher(algo_spec))
      stream_cipher_cache.set_preferred_provider(algo_spec, provider);
   else if(prototype_hash_function(algo_spec))
      hash_cache.set_preferred_provider(algo_spec, provider);
   else if(prototype_mac(algo_spec))
      mac_cache.set_preferred_provider(algo_spec, provider);
   }

/**
* Get an engine out of the list
*/
Engine* Algorithm_Factory::get_engine_n(u32bit n) const
   {
   if(n >= engines.size())
      return 0;
   return engines[n];
   }

/**
* Return the possible providers of a request
* Note: assumes you don't have different types by the same name
*/
std::vector<std::string>
Algorithm_Factory::providers_of(const std::string& algo_spec)
   {
   if(prototype_block_cipher(algo_spec))
      return block_cipher_cache.providers_of(algo_spec);
   else if(prototype_stream_cipher(algo_spec))
      return stream_cipher_cache.providers_of(algo_spec);
   else if(prototype_hash_function(algo_spec))
      return hash_cache.providers_of(algo_spec);
   else if(prototype_mac(algo_spec))
      return mac_cache.providers_of(algo_spec);
   else
      return std::vector<std::string>();
   }

/**
* Return the prototypical block cipher cooresponding to this request
*/
const BlockCipher*
Algorithm_Factory::prototype_block_cipher(const std::string& algo_spec,
                                          const std::string& provider)
   {
   if(const BlockCipher* hit = block_cipher_cache.get(algo_spec, provider))
      return hit;

   SCAN_Name scan_name(algo_spec);
   for(u32bit i = 0; i != engines.size(); ++i)
      {
      if(BlockCipher* impl = engines[i]->find_block_cipher(scan_name, *this))
         block_cipher_cache.add(impl, algo_spec, engines[i]->provider_name());
      }

   return block_cipher_cache.get(algo_spec, provider);
   }

/**
* Return the prototypical stream cipher cooresponding to this request
*/
const StreamCipher*
Algorithm_Factory::prototype_stream_cipher(const std::string& algo_spec,
                                           const std::string& provider)
   {
   if(const StreamCipher* hit = stream_cipher_cache.get(algo_spec, provider))
      return hit;

   SCAN_Name scan_name(algo_spec);
   for(u32bit i = 0; i != engines.size(); ++i)
      {
      if(StreamCipher* impl = engines[i]->find_stream_cipher(scan_name, *this))
         stream_cipher_cache.add(impl, algo_spec, engines[i]->provider_name());
      }

   return stream_cipher_cache.get(algo_spec, provider);
   }

/**
* Return the prototypical object cooresponding to this request (if found)
*/
const HashFunction*
Algorithm_Factory::prototype_hash_function(const std::string& algo_spec,
                                           const std::string& provider)
   {
   if(const HashFunction* hit = hash_cache.get(algo_spec, provider))
      return hit;

   SCAN_Name scan_name(algo_spec);
   for(u32bit i = 0; i != engines.size(); ++i)
      {
      if(HashFunction* impl = engines[i]->find_hash(scan_name, *this))
         hash_cache.add(impl, algo_spec, engines[i]->provider_name());
      }

   return hash_cache.get(algo_spec, provider);
   }

/**
* Return the prototypical object cooresponding to this request
*/
const MessageAuthenticationCode*
Algorithm_Factory::prototype_mac(const std::string& algo_spec,
                                 const std::string& provider)
   {
   if(const MessageAuthenticationCode* hit = mac_cache.get(algo_spec, provider))
      return hit;

   SCAN_Name scan_name(algo_spec);
   for(u32bit i = 0; i != engines.size(); ++i)
      {
      if(MessageAuthenticationCode* impl = engines[i]->find_mac(scan_name, *this))
         mac_cache.add(impl, algo_spec, engines[i]->provider_name());
      }

   return mac_cache.get(algo_spec, provider);
   }

/**
* Return a new block cipher cooresponding to this request
*/
BlockCipher* Algorithm_Factory::make_block_cipher(const std::string& algo_spec,
                                                  const std::string& provider)
   {
   if(const BlockCipher* proto = prototype_block_cipher(algo_spec, provider))
      return proto->clone();
   throw Algorithm_Not_Found(algo_spec);
   }

/**
* Return a new stream cipher cooresponding to this request
*/
StreamCipher* Algorithm_Factory::make_stream_cipher(const std::string& algo_spec,
                                                    const std::string& provider)
   {
   if(const StreamCipher* prototype = prototype_stream_cipher(algo_spec, provider))
      return prototype->clone();
   throw Algorithm_Not_Found(algo_spec);
   }

/**
* Return a new object cooresponding to this request
*/
HashFunction* Algorithm_Factory::make_hash_function(const std::string& algo_spec,
                                                    const std::string& provider)
   {
   if(const HashFunction* prototype = prototype_hash_function(algo_spec, provider))
      return prototype->clone();
   throw Algorithm_Not_Found(algo_spec);
   }

/**
* Return a new object cooresponding to this request
*/
MessageAuthenticationCode*
Algorithm_Factory::make_mac(const std::string& algo_spec,
                            const std::string& provider)
   {
   if(const MessageAuthenticationCode* prototype = prototype_mac(algo_spec, provider))
      return prototype->clone();
   throw Algorithm_Not_Found(algo_spec);
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
* Add a new stream cipher
*/
void Algorithm_Factory::add_stream_cipher(StreamCipher* stream_cipher,
                                         const std::string& provider)
   {
   stream_cipher_cache.add(stream_cipher, stream_cipher->name(), provider);
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
* Add a new mac
*/
void Algorithm_Factory::add_mac(MessageAuthenticationCode* mac,
                                const std::string& provider)
   {
   mac_cache.add(mac, mac->name(), provider);
   }

}
