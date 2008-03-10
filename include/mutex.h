/*************************************************
* Mutex Header File                              *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_MUTEX_H__
#define BOTAN_MUTEX_H__

#include <botan/exceptn.h>

namespace Botan {

/*************************************************
* Mutex Base Class                               *
*************************************************/
class Mutex
   {
   public:
      virtual void lock() = 0;
      virtual void unlock() = 0;
      virtual ~Mutex() {}
   };

/*************************************************
* Mutex Factory                                  *
*************************************************/
class Mutex_Factory
   {
   public:
      virtual Mutex* make() = 0;
      virtual ~Mutex_Factory() {}
   };

/*************************************************
* Default Mutex Factory                          *
*************************************************/
class Default_Mutex_Factory : public Mutex_Factory
   {
   public:
      Mutex* make();
   };

/*************************************************
* Mutex Holding Class                            *
*************************************************/
class Mutex_Holder
   {
   public:
      Mutex_Holder(Mutex*);
      ~Mutex_Holder();
   private:
      Mutex* mux;
   };

/*************************************************
* Named Mutex Holder                             *
*************************************************/
class Named_Mutex_Holder
   {
   public:
      Named_Mutex_Holder(const std::string&);
      ~Named_Mutex_Holder();
   private:
      const std::string mutex_name;
   };

}

#endif
