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

Algorithm_Factory::Algorithm_Factory(Mutex_Factory& mf) :
   mutex_factory(mf),
   hash_cache(mf.make())
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
* Add a new engine to the list
*/
void Algorithm_Factory::add_engine(Engine* engine)
   {
   engine->initialize(mutex_factory);
   engines.insert(engines.begin(), engine);
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
Algorithm_Factory::providers_of(const SCAN_Name& request)
   {
   std::vector<std::string> providers;
   for(u32bit i = 0; i != engines.size(); ++i)
      {
      std::string provider = engines[i]->provider_name();
      if(request.provider_allowed(provider))
         {
         if(engines[i]->prototype_block_cipher(request, *this) ||
            engines[i]->prototype_stream_cipher(request, *this) ||
            engines[i]->prototype_hash_function(request, *this) ||
            engines[i]->prototype_mac(request, *this))
            {
            providers.push_back(provider);
            }
         }
      }

   return providers;
   }

/**
* Return the prototypical object cooresponding to this request
*/
const BlockCipher*
Algorithm_Factory::prototype_block_cipher(const SCAN_Name& request)
   {
   for(u32bit i = 0; i != engines.size(); ++i)
      {
      if(request.provider_allowed(engines[i]->provider_name()))
         {
         const BlockCipher* algo =
            engines[i]->prototype_block_cipher(request, *this);

         if(algo)
            return algo;
         }
      }

   return 0;
   }

/**
* Return a new object cooresponding to this request
*/
BlockCipher* Algorithm_Factory::make_block_cipher(const SCAN_Name& request)
   {
   const BlockCipher* prototype = prototype_block_cipher(request);
   if(prototype)
      return prototype->clone();

   throw Algorithm_Not_Found(request.as_string());
   }

/**
* Add a new object
*/
void Algorithm_Factory::add_block_cipher(BlockCipher* hash)
   {
   for(u32bit i = 0; i != engines.size(); ++i)
      {
      if(engines[i]->can_add_algorithms())
         {
         engines[i]->add_algorithm(hash);
         return;
         }
      }

   throw Exception("Algorithm_Factory::add_block_cipher: No engine found");
   }

/**
* Return the prototypical object cooresponding to this request
*/
const StreamCipher*
Algorithm_Factory::prototype_stream_cipher(const SCAN_Name& request)
   {
   for(u32bit i = 0; i != engines.size(); ++i)
      {
      if(request.provider_allowed(engines[i]->provider_name()))
         {
         const StreamCipher* algo =
            engines[i]->prototype_stream_cipher(request, *this);

         if(algo)
            return algo;
         }
      }

   return 0;
   }

/**
* Return a new object cooresponding to this request
*/
StreamCipher* Algorithm_Factory::make_stream_cipher(const SCAN_Name& request)
   {
   const StreamCipher* prototype = prototype_stream_cipher(request);
   if(prototype)
      return prototype->clone();

   throw Algorithm_Not_Found(request.as_string());
   }

/**
* Add a new object
*/
void Algorithm_Factory::add_stream_cipher(StreamCipher* hash)
   {
   for(u32bit i = 0; i != engines.size(); ++i)
      {
      if(engines[i]->can_add_algorithms())
         {
         engines[i]->add_algorithm(hash);
         return;
         }
      }

   throw Exception("Algorithm_Factory::add_stream_cipher: No engine found");
   }

/**
* Return the prototypical object cooresponding to this request
*/
const HashFunction*
Algorithm_Factory::prototype_hash_function(const SCAN_Name& request)
   {
#if 1
   for(u32bit i = 0; i != engines.size(); ++i)
      {
      if(request.provider_allowed(engines[i]->provider_name()))
         {
         const HashFunction* algo =
            engines[i]->prototype_hash_function(request, *this);

         if(algo)
            return algo;
         }
      }

   return 0;
#else
   const HashFunction* cache_hit = hash_cache.get(request);
   if(cache_hit)
      return cache_hit;

   // Search for all providers of this algorithm and add them to the cache
   for(u32bit i = 0; i != engines.size(); ++i)
      {
      const std::string provider = engines[i]->provider_name();
      HashFunction* impl = engines[i]->find_hash(request, *this);

      if(impl)
         hash_cache.add(impl, provider);
      }

   /* Now try the cache search again (if the providers don't match up
      with ones that exist in this build, this might still fail and
      return 0).
   */

   return hash_cache.get(request);
#endif
   }

/**
* Return a new object cooresponding to this request
*/
HashFunction* Algorithm_Factory::make_hash_function(const SCAN_Name& request)
   {
   const HashFunction* prototype = prototype_hash_function(request);
   if(prototype)
      return prototype->clone();

   throw Algorithm_Not_Found(request.as_string());
   }

/**
* Add a new object
*/
void Algorithm_Factory::add_hash_function(HashFunction* hash)
   {
   for(u32bit i = 0; i != engines.size(); ++i)
      {
      if(engines[i]->can_add_algorithms())
         {
         engines[i]->add_algorithm(hash);
         return;
         }
      }

   throw Exception("Algorithm_Factory::add_hash_function: No engine found");
   }

/**
* Return the prototypical object cooresponding to this request
*/
const MessageAuthenticationCode*
Algorithm_Factory::prototype_mac(const SCAN_Name& request)
   {
   for(u32bit i = 0; i != engines.size(); ++i)
      {
      if(request.provider_allowed(engines[i]->provider_name()))
         {
         const MessageAuthenticationCode* algo =
            engines[i]->prototype_mac(request, *this);

         if(algo)
            return algo;
         }
      }

   return 0;
   }

/**
* Return a new object cooresponding to this request
*/
MessageAuthenticationCode*
Algorithm_Factory::make_mac(const SCAN_Name& request)
   {
   const MessageAuthenticationCode* prototype = prototype_mac(request);
   if(prototype)
      return prototype->clone();

   throw Algorithm_Not_Found(request.as_string());
   }

/**
* Add a new object
*/
void Algorithm_Factory::add_mac(MessageAuthenticationCode* hash)
   {
   for(u32bit i = 0; i != engines.size(); ++i)
      {
      if(engines[i]->can_add_algorithms())
         {
         engines[i]->add_algorithm(hash);
         return;
         }
      }

   throw Exception("Algorithm_Factory::add_mac: No engine found");
   }

}
