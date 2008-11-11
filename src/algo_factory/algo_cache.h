/**
* An algorithm cache (used by Algorithm_Factory)
*/

#ifndef BOTAN_ALGORITHM_CACHE_TEMPLATE_H__
#define BOTAN_ALGORITHM_CACHE_TEMPLATE_H__

#include <botan/scan_name.h>
#include <botan/mutex.h>
#include <stdexcept>
#include <map>
#include <string>

namespace Botan {

template<typename T>
class Algorithm_Cache
   {
   public:
      const T* get(const SCAN_Name& request);
      void add(T* algo,
               const std::string& requested_name,
               const std::string& provider);

      std::vector<std::string> providers_of(const std::string& algo_name);

      Algorithm_Cache(Mutex* m) : mutex(m) {}
      ~Algorithm_Cache();
   private:
      typedef typename std::map<std::string, std::map<std::string, T*> >::iterator algorithms_iterator;
      typedef typename std::map<std::string, T*>::iterator provider_iterator;

      algorithms_iterator find_algorithm(const std::string& algo_spec);

      Mutex* mutex;
      std::map<std::string, std::string> aliases;
      std::map<std::string, std::map<std::string, T*> > algorithms;

   };

/**
* Look for an algorithm implementation in the cache, also checking aliases
*/
template<typename T>
typename Algorithm_Cache<T>::algorithms_iterator
Algorithm_Cache<T>::find_algorithm(const std::string& algo_spec)
   {
   // Assumes mutex is held
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

/**
* Look for an algorithm implementation in the cache
*/
template<typename T>
const T* Algorithm_Cache<T>::get(const SCAN_Name& request)
   {
   Mutex_Holder lock(mutex);

   algorithms_iterator algo = find_algorithm(request.as_string());
   if(algo == algorithms.end()) // not found at all
      return 0;

   const std::string requested_provider = request.provider();

   if(requested_provider != "") // If a specific request, allow that provider or core
      {
      provider_iterator provider = algo->second.find(requested_provider);

      if(provider != algo->second.end())
         return provider->second;
      }
   else // no specific provider requested: pick one
      {
      printf("No specific provider requested for %s\n", request.as_string().c_str());
      provider_iterator provider = algo->second.begin();

      while(provider != algo->second.end())
         ++provider;

      provider = algo->second.begin();
      // @fixme: Just picks the lexicographically first one
      if(provider != algo->second.end())
         return provider->second;
      }

   return 0; // cache miss
   }

/**
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

   delete algorithms[algo->name()][provider];
   algorithms[algo->name()][provider] = algo;

   if(algo->name() != requested_name && aliases.find(requested_name) == aliases.end())
      aliases[requested_name] = algo->name();
   }

/**
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

/**
* Algorithm_Cache<T> Destructor
*/
template<typename T>
Algorithm_Cache<T>::~Algorithm_Cache()
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

   delete mutex;
   }

}

#endif
