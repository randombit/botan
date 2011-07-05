/*
* An algorithm cache (used by Algorithm_Factory)
* (C) 2008-2009,2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ALGORITHM_CACHE_TEMPLATE_H__
#define BOTAN_ALGORITHM_CACHE_TEMPLATE_H__

#include <botan/internal/mutex.h>
#include <botan/internal/stl_util.h>
#include <string>
#include <vector>
#include <map>

namespace Botan {

/**
* @param prov_name a provider name
* @return weight for this provider
*/
size_t static_provider_weight(const std::string& prov_name);

/**
* Algorithm_Cache (used by Algorithm_Factory)
*/
template<typename T>
class Algorithm_Cache
   {
   public:
      /**
      * @param algo_spec names the requested algorithm
      * @param pref_provider suggests a preferred provider
      * @return prototype object, or NULL
      */
      const T* get(const std::string& algo_spec,
                   const std::string& pref_provider);

      /**
      * Add a new algorithm implementation to the cache
      * @param algo the algorithm prototype object
      * @param requested_name how this name will be requested
      * @param provider_name is the name of the provider of this prototype
      */
      void add(T* algo,
               const std::string& requested_name,
               const std::string& provider_name);

      /**
      * Set the preferred provider
      * @param algo_spec names the algorithm
      * @param provider names the preferred provider
      */
      void set_preferred_provider(const std::string& algo_spec,
                                  const std::string& provider);

      /**
      * Return the list of providers of this algorithm
      * @param algo_name names the algorithm
      * @return list of providers of this algorithm
      */
      std::vector<std::string> providers_of(const std::string& algo_name);

      /**
      * Clear the cache
      */
      void clear_cache();

      /**
      * Constructor
      * @param m a mutex to serialize internal access
      */
      Algorithm_Cache(Mutex* m) : mutex(m) {}
      ~Algorithm_Cache() { clear_cache(); delete mutex; }
   private:
      typedef typename std::map<std::string, std::map<std::string, T*> >::iterator
         algorithms_iterator;

      typedef typename std::map<std::string, T*>::iterator provider_iterator;

      algorithms_iterator find_algorithm(const std::string& algo_spec);

      Mutex* mutex;
      std::map<std::string, std::string> aliases;
      std::map<std::string, std::string> pref_providers;
      std::map<std::string, std::map<std::string, T*> > algorithms;
   };

/*
* Look for an algorithm implementation in the cache, also checking aliases
* Assumes object lock is held
*/
template<typename T>
typename Algorithm_Cache<T>::algorithms_iterator
Algorithm_Cache<T>::find_algorithm(const std::string& algo_spec)
   {
   algorithms_iterator algo = algorithms.find(algo_spec);

   // Not found? Check if a known alias
   if(algo == algorithms.end())
      {
      std::map<std::string, std::string>::const_iterator alias =
         aliases.find(algo_spec);

      if(alias != aliases.end())
         algo = algorithms.find(alias->second);
      }

   return algo;
   }

/*
* Look for an algorithm implementation by a particular provider
*/
template<typename T>
const T* Algorithm_Cache<T>::get(const std::string& algo_spec,
                                 const std::string& requested_provider)
   {
   Mutex_Holder lock(mutex);

   algorithms_iterator algo = find_algorithm(algo_spec);
   if(algo == algorithms.end()) // algo not found at all (no providers)
      return 0;

   // If a provider is requested specifically, return it or fail entirely
   if(requested_provider != "")
      {
      provider_iterator prov = algo->second.find(requested_provider);
      if(prov != algo->second.end())
         return prov->second;
      return 0;
      }

   const T* prototype = 0;
   std::string prototype_provider;
   size_t prototype_prov_weight = 0;

   const std::string pref_provider = search_map(pref_providers, algo_spec);

   for(provider_iterator i = algo->second.begin(); i != algo->second.end(); ++i)
      {
      const std::string prov_name = i->first;
      const size_t prov_weight = static_provider_weight(prov_name);

      // preferred prov exists, return immediately
      if(prov_name == pref_provider)
         return i->second;

      if(prototype == 0 || prov_weight > prototype_prov_weight)
         {
         prototype = i->second;
         prototype_provider = i->first;
         prototype_prov_weight = prov_weight;
         }
      }

   return prototype;
   }

/*
* Add an implementation to the cache
*/
template<typename T>
void Algorithm_Cache<T>::add(T* algo,
                             const std::string& requested_name,
                             const std::string& provider)
   {
   if(!algo)
      return;

   Mutex_Holder lock(mutex);

   if(algo->name() != requested_name &&
      aliases.find(requested_name) == aliases.end())
      {
      aliases[requested_name] = algo->name();
      }

   if(!algorithms[algo->name()][provider])
      algorithms[algo->name()][provider] = algo;
   else
      delete algo;
   }

/*
* Find the providers of this algo (if any)
*/
template<typename T> std::vector<std::string>
Algorithm_Cache<T>::providers_of(const std::string& algo_name)
   {
   Mutex_Holder lock(mutex);

   std::vector<std::string> providers;

   algorithms_iterator algo = find_algorithm(algo_name);

   if(algo != algorithms.end())
      {
      provider_iterator provider = algo->second.begin();

      while(provider != algo->second.end())
         {
         providers.push_back(provider->first);
         ++provider;
         }
      }

   return providers;
   }

/*
* Set the preferred provider for an algorithm
*/
template<typename T>
void Algorithm_Cache<T>::set_preferred_provider(const std::string& algo_spec,
                                                const std::string& provider)
   {
   Mutex_Holder lock(mutex);

   pref_providers[algo_spec] = provider;
   }

/*
* Clear out the cache
*/
template<typename T>
void Algorithm_Cache<T>::clear_cache()
   {
   algorithms_iterator algo = algorithms.begin();

   while(algo != algorithms.end())
      {
      provider_iterator provider = algo->second.begin();

      while(provider != algo->second.end())
         {
         delete provider->second;
         ++provider;
         }

      ++algo;
      }

   algorithms.clear();
   }

}

#endif
