/*************************************************
* Module Factory Header File                     *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_MODULE_FACTORIES_H__
#define BOTAN_MODULE_FACTORIES_H__

#include <botan/init.h>
#include <string>
#include <vector>

namespace Botan {

/*************************************************
* Module Builder Interface                       *
*************************************************/
class Modules
   {
   public:
      virtual class Mutex_Factory* mutex_factory() const = 0;
      virtual class Timer* timer() const = 0;
      virtual class Charset_Transcoder* transcoder() const = 0;

      virtual std::string default_allocator() const = 0;

      virtual std::vector<class Allocator*> allocators() const = 0;
      virtual std::vector<class EntropySource*> entropy_sources() const = 0;
      virtual std::vector<class Engine*> engines() const = 0;

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
      class Charset_Transcoder* transcoder() const;

      std::string default_allocator() const;

      std::vector<class Allocator*> allocators() const;
      std::vector<class EntropySource*> entropy_sources() const;
      std::vector<class Engine*> engines() const;

      Builtin_Modules(const InitializerOptions&);
   private:
      const bool should_lock, use_engines;
   };

}

#endif
