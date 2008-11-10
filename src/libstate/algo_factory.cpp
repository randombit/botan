/*
Algorithm Factory
(C) 2008 Jack Lloyd
*/

#include <botan/libstate.h>
#include <botan/stl_util.h>
#include <botan/engine.h>
#include <algorithm>

namespace Botan {

/**
* Delete all engines
*/
Algorithm_Factory::~Algorithm_Factory()
   {
   std::for_each(engines.begin(), engines.end(), del_fun<Engine>());
   engines.clear();

   delete mutex;
   }

/**
* Add a new engine to the list
*/
void Algorithm_Factory::add_engine(Engine* engine)
   {
   Mutex_Holder lock(mutex);
   engines.insert(engines.begin(), engine);
   }

/*************************************************
* Get an engine out of the list                  *
*************************************************/
Engine* Algorithm_Factory::get_engine_n(u32bit n) const
   {
   Mutex_Holder lock(mutex);

   if(n >= engines.size())
      return 0;
   return engines[n];
   }

const HashFunction* Algorithm_Factory::prototype_hash_function(const std::string& algo_spec)
   {
   Mutex_Holder lock(mutex);

   for(u32bit i = 0; i != engines.size(); ++i)
      {
      const HashFunction* algo = engines[i]->hash(algo_spec);
      if(algo)
         return algo;
      }

   return 0;
   }

}
