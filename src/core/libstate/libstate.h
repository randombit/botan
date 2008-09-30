/*************************************************
* Library Internal/Global State Header File      *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_LIB_STATE_H__
#define BOTAN_LIB_STATE_H__

#include <botan/base.h>
#include <botan/init.h>
#include <string>
#include <vector>
#include <map>

namespace Botan {

/*************************************************
* Global State Container Base                    *
*************************************************/
class BOTAN_DLL Library_State
   {
   public:
      Library_State();
      ~Library_State();

      void initialize(const InitializerOptions&, Modules&);

      void load(Modules&);

      void add_engine(class Engine*);

      class BOTAN_DLL Engine_Iterator
         {
         public:
            class Engine* next();
            Engine_Iterator(const Library_State& l) : lib(l) { n = 0; }
         private:
            const Library_State& lib;
            u32bit n;
         };
      friend class Engine_Iterator;

      Allocator* get_allocator(const std::string& = "") const;
      void add_allocator(Allocator*);
      void set_default_allocator(const std::string&);

      std::string get(const std::string&, const std::string&) const;
      bool is_set(const std::string&, const std::string&) const;
      void set(const std::string&, const std::string&,
               const std::string&, bool = true);

      std::string option(const std::string&) const;
      void set_option(const std::string, const std::string&);

      void add_alias(const std::string&, const std::string&);
      std::string deref_alias(const std::string&) const;

      class Mutex* get_mutex() const;
   private:
      void load_default_config();

      Library_State(const Library_State&) {}
      Library_State& operator=(const Library_State&) { return (*this); }

      class Engine* get_engine_n(u32bit) const;

      class Mutex_Factory* mutex_factory;

      std::map<std::string, std::string> config;
      class Mutex* config_lock;

      class Mutex* allocator_lock;
      std::map<std::string, Allocator*> alloc_factory;
      mutable Allocator* cached_default_allocator;
      std::vector<Allocator*> allocators;

      class Mutex* engine_lock;
      std::vector<class Engine*> engines;
   };

/*************************************************
* Global State                                   *
*************************************************/
BOTAN_DLL Library_State& global_state();
BOTAN_DLL void set_global_state(Library_State*);
BOTAN_DLL Library_State* swap_global_state(Library_State*);

}

#endif
