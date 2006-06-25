/*************************************************
* Module Factory Header File                     *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_MODULE_FACTORIES_H__
#define BOTAN_MODULE_FACTORIES_H__

#include <string>
#include <vector>

namespace Botan {

/*************************************************
* Module Builder Interface                       *
*************************************************/
class Modules
   {
   public:
      void load(class Library_State&) const;

      virtual class Mutex_Factory* mutex_factory() const;
      virtual class Timer* timer() const;

      virtual std::vector<class Allocator*> allocators() const;
      virtual std::vector<class EntropySource*> entropy_sources() const;
      virtual std::vector<class Engine*> engines() const;

      virtual ~Modules() {}
   };

/*************************************************
* Built In Modules                               *
*************************************************/
class Builtin_Modules : public Modules
   {
   public:
      class Mutex_Factory* mutex_factory() const;
      class Timer* timer() const;

      std::vector<class Allocator*> allocators() const;
      std::vector<class EntropySource*> entropy_sources() const;
      std::vector<class Engine*> engines() const;
   };

}

#endif
