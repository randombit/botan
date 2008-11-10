/*
Algorithm Factory
(C) 2008 Jack Lloyd
*/

#include <botan/libstate.h>
#include <botan/stl_util.h>
#include <botan/engine.h>
#include <botan/exceptn.h>
#include <algorithm>

namespace Botan {

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
* Return the prototypical object cooresponding to this request
*/
const HashFunction*
Algorithm_Factory::prototype_hash_function(const SCAN_Name& request)
   {
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

}
