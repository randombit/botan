/*************************************************
* Module Factory Header File                     *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_MODULE_FACTORIES_H__
#define BOTAN_MODULE_FACTORIES_H__

namespace Botan {

/*************************************************
* Module Builder Interface                       *
*************************************************/
class Modules
   {
   public:
      void load(class Library_State&) const;

      virtual class Mutex_Factory* mutex_factory() const { return 0; }
      virtual class Timer* timer() const { return 0; }

      virtual void set_allocators(class Library_State&, bool) const {}
      virtual void set_entropy_sources(class Library_State&) const {}
      virtual void set_engines(class Library_State&, bool) const {}

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

      void set_allocators(class Library_State&, bool) const;
      void set_entropy_sources(class Library_State&) const;
      void set_engines(class Library_State&, bool) const;
   };

}

#endif
