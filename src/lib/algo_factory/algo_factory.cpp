/*
* Algorithm Factory
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/algo_factory.h>
#include <botan/internal/algo_cache.h>
#include <botan/internal/stl_util.h>
#include <botan/engine.h>
#include <botan/exceptn.h>

#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/pbkdf.h>

#include <algorithm>

namespace Botan {

namespace {

/*
* Template functions for the factory prototype/search algorithm
*/
template<typename T>
T* engine_get_algo(Engine*,
                   const SCAN_Name&,
                   Algorithm_Factory&)
   { return nullptr; }

template<>
BlockCipher* engine_get_algo(Engine* engine,
                             const SCAN_Name& request,
                             Algorithm_Factory& af)
   { return engine->find_block_cipher(request, af); }

template<>
StreamCipher* engine_get_algo(Engine* engine,
                              const SCAN_Name& request,
                              Algorithm_Factory& af)
   { return engine->find_stream_cipher(request, af); }

template<>
HashFunction* engine_get_algo(Engine* engine,
                              const SCAN_Name& request,
                              Algorithm_Factory& af)
   { return engine->find_hash(request, af); }

template<>
MessageAuthenticationCode* engine_get_algo(Engine* engine,
                                           const SCAN_Name& request,
                                           Algorithm_Factory& af)
   { return engine->find_mac(request, af); }

template<>
PBKDF* engine_get_algo(Engine* engine,
                       const SCAN_Name& request,
                       Algorithm_Factory& af)
   { return engine->find_pbkdf(request, af); }

template<typename T>
const T* factory_prototype(const std::string& algo_spec,
                           const std::string& provider,
                           const std::vector<Engine*>& engines,
                           Algorithm_Factory& af,
                           Algorithm_Cache<T>* cache)
   {
   if(const T* cache_hit = cache->get(algo_spec, provider))
      return cache_hit;

   SCAN_Name scan_name(algo_spec);

   if(scan_name.cipher_mode() != "")
      return nullptr;

   for(size_t i = 0; i != engines.size(); ++i)
      {
      if(provider == "" || engines[i]->provider_name() == provider)
         {
         if(T* impl = engine_get_algo<T>(engines[i], scan_name, af))
            cache->add(impl, algo_spec, engines[i]->provider_name());
         }
      }

   return cache->get(algo_spec, provider);
   }

}

/*
* Setup caches
*/
Algorithm_Factory::Algorithm_Factory()
   {
   block_cipher_cache = new Algorithm_Cache<BlockCipher>();
   stream_cipher_cache = new Algorithm_Cache<StreamCipher>();
   hash_cache = new Algorithm_Cache<HashFunction>();
   mac_cache = new Algorithm_Cache<MessageAuthenticationCode>();
   pbkdf_cache = new Algorithm_Cache<PBKDF>();
   }

/*
* Delete all engines
*/
Algorithm_Factory::~Algorithm_Factory()
   {
   delete block_cipher_cache;
   delete stream_cipher_cache;
   delete hash_cache;
   delete mac_cache;
   delete pbkdf_cache;

   for(auto i = engines.begin(); i != engines.end(); ++i)
      delete *i;
   }

void Algorithm_Factory::clear_caches()
   {
   block_cipher_cache->clear_cache();
   stream_cipher_cache->clear_cache();
   hash_cache->clear_cache();
   mac_cache->clear_cache();
   pbkdf_cache->clear_cache();
   }

void Algorithm_Factory::add_engine(Engine* engine)
   {
   clear_caches();
   engines.push_back(engine);
   }

/*
* Set the preferred provider for an algorithm
*/
void Algorithm_Factory::set_preferred_provider(const std::string& algo_spec,
                                               const std::string& provider)
   {
   if(prototype_block_cipher(algo_spec))
      block_cipher_cache->set_preferred_provider(algo_spec, provider);
   else if(prototype_stream_cipher(algo_spec))
      stream_cipher_cache->set_preferred_provider(algo_spec, provider);
   else if(prototype_hash_function(algo_spec))
      hash_cache->set_preferred_provider(algo_spec, provider);
   else if(prototype_mac(algo_spec))
      mac_cache->set_preferred_provider(algo_spec, provider);
   else if(prototype_pbkdf(algo_spec))
      pbkdf_cache->set_preferred_provider(algo_spec, provider);
   }

/*
* Get an engine out of the list
*/
Engine* Algorithm_Factory::get_engine_n(size_t n) const
   {
   if(n >= engines.size())
      return nullptr;
   return engines[n];
   }

/*
* Return the possible providers of a request
* Note: assumes you don't have different types by the same name
*/
std::vector<std::string>
Algorithm_Factory::providers_of(const std::string& algo_spec)
   {
   /* The checks with if(prototype_X(algo_spec)) have the effect of
      forcing a full search, since otherwise there might not be any
      providers at all in the cache.
   */

   if(prototype_block_cipher(algo_spec))
      return block_cipher_cache->providers_of(algo_spec);
   else if(prototype_stream_cipher(algo_spec))
      return stream_cipher_cache->providers_of(algo_spec);
   else if(prototype_hash_function(algo_spec))
      return hash_cache->providers_of(algo_spec);
   else if(prototype_mac(algo_spec))
      return mac_cache->providers_of(algo_spec);
   else if(prototype_pbkdf(algo_spec))
      return pbkdf_cache->providers_of(algo_spec);
   else
      return std::vector<std::string>();
   }

/*
* Return the prototypical block cipher corresponding to this request
*/
const BlockCipher*
Algorithm_Factory::prototype_block_cipher(const std::string& algo_spec,
                                          const std::string& provider)
   {
   return factory_prototype<BlockCipher>(algo_spec, provider, engines,
                                          *this, block_cipher_cache);
   }

/*
* Return the prototypical stream cipher corresponding to this request
*/
const StreamCipher*
Algorithm_Factory::prototype_stream_cipher(const std::string& algo_spec,
                                           const std::string& provider)
   {
   return factory_prototype<StreamCipher>(algo_spec, provider, engines,
                                          *this, stream_cipher_cache);
   }

/*
* Return the prototypical object corresponding to this request (if found)
*/
const HashFunction*
Algorithm_Factory::prototype_hash_function(const std::string& algo_spec,
                                           const std::string& provider)
   {
   return factory_prototype<HashFunction>(algo_spec, provider, engines,
                                          *this, hash_cache);
   }

/*
* Return the prototypical object corresponding to this request
*/
const MessageAuthenticationCode*
Algorithm_Factory::prototype_mac(const std::string& algo_spec,
                                 const std::string& provider)
   {
   return factory_prototype<MessageAuthenticationCode>(algo_spec, provider,
                                                       engines,
                                                       *this, mac_cache);
   }

/*
* Return the prototypical object corresponding to this request
*/
const PBKDF*
Algorithm_Factory::prototype_pbkdf(const std::string& algo_spec,
                                   const std::string& provider)
   {
   return factory_prototype<PBKDF>(algo_spec, provider,
                                   engines,
                                   *this, pbkdf_cache);
   }

/*
* Return a new block cipher corresponding to this request
*/
BlockCipher*
Algorithm_Factory::make_block_cipher(const std::string& algo_spec,
                                     const std::string& provider)
   {
   if(const BlockCipher* proto = prototype_block_cipher(algo_spec, provider))
      return proto->clone();
   throw Algorithm_Not_Found(algo_spec);
   }

/*
* Return a new stream cipher corresponding to this request
*/
StreamCipher*
Algorithm_Factory::make_stream_cipher(const std::string& algo_spec,
                                      const std::string& provider)
   {
   if(const StreamCipher* proto = prototype_stream_cipher(algo_spec, provider))
      return proto->clone();
   throw Algorithm_Not_Found(algo_spec);
   }

/*
* Return a new object corresponding to this request
*/
HashFunction*
Algorithm_Factory::make_hash_function(const std::string& algo_spec,
                                      const std::string& provider)
   {
   if(const HashFunction* proto = prototype_hash_function(algo_spec, provider))
      return proto->clone();
   throw Algorithm_Not_Found(algo_spec);
   }

/*
* Return a new object corresponding to this request
*/
MessageAuthenticationCode*
Algorithm_Factory::make_mac(const std::string& algo_spec,
                            const std::string& provider)
   {
   if(const MessageAuthenticationCode* proto = prototype_mac(algo_spec, provider))
      return proto->clone();
   throw Algorithm_Not_Found(algo_spec);
   }

/*
* Return a new object corresponding to this request
*/
PBKDF*
Algorithm_Factory::make_pbkdf(const std::string& algo_spec,
                              const std::string& provider)
   {
   if(const PBKDF* proto = prototype_pbkdf(algo_spec, provider))
      return proto->clone();
   throw Algorithm_Not_Found(algo_spec);
   }

/*
* Add a new block cipher
*/
void Algorithm_Factory::add_block_cipher(BlockCipher* block_cipher,
                                         const std::string& provider)
   {
   block_cipher_cache->add(block_cipher, block_cipher->name(), provider);
   }

/*
* Add a new stream cipher
*/
void Algorithm_Factory::add_stream_cipher(StreamCipher* stream_cipher,
                                         const std::string& provider)
   {
   stream_cipher_cache->add(stream_cipher, stream_cipher->name(), provider);
   }

/*
* Add a new hash
*/
void Algorithm_Factory::add_hash_function(HashFunction* hash,
                                          const std::string& provider)
   {
   hash_cache->add(hash, hash->name(), provider);
   }

/*
* Add a new mac
*/
void Algorithm_Factory::add_mac(MessageAuthenticationCode* mac,
                                const std::string& provider)
   {
   mac_cache->add(mac, mac->name(), provider);
   }

/*
* Add a new PBKDF
*/
void Algorithm_Factory::add_pbkdf(PBKDF* pbkdf,
                                  const std::string& provider)
   {
   pbkdf_cache->add(pbkdf, pbkdf->name(), provider);
   }

}
