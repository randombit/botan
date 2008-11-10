/**
* Algorithm Factory
* (C) 2008 Jack Lloyd
*/

#ifndef BOTAN_ALGORITHM_FACTORY_H__
#define BOTAN_ALGORITHM_FACTORY_H__

#include <botan/scan_name.h>
#include <botan/mutex.h>
#include <botan/hash.h>
#include <string>
#include <vector>

namespace Botan {

/**
* Algorithm Factory
*/
class BOTAN_DLL Algorithm_Factory
   {
   public:
      ~Algorithm_Factory();

      const HashFunction* prototype_hash_function(const SCAN_Name& request);
      HashFunction* make_hash_function(const SCAN_Name& request);

      void add_engine(class Engine*);

      class BOTAN_DLL Engine_Iterator
         {
         public:
            class Engine* next() { return af.get_engine_n(n++); }
            Engine_Iterator(const Algorithm_Factory& a) : af(a) { n = 0; }
         private:
            const Algorithm_Factory& af;
            u32bit n;
         };
      friend class Engine_Iterator;

   private:
      class Engine* get_engine_n(u32bit) const;

      std::vector<class Engine*> engines;
   };

}

#endif
