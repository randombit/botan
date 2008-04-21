/*************************************************
* Mutex Header File                              *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_MUTEX_H__
#define BOTAN_MUTEX_H__

#include <botan/exceptn.h>

namespace Botan {

/*************************************************
* Mutex Base Class                               *
*************************************************/
class BOTAN_DLL Mutex
   {
   public:
      virtual void lock() = 0;
      virtual void unlock() = 0;
      virtual ~Mutex() {}
   };

/*************************************************
* Mutex Factory                                  *
*************************************************/
class BOTAN_DLL Mutex_Factory
   {
   public:
      virtual Mutex* make() = 0;
      virtual ~Mutex_Factory() {}
   };

/*************************************************
* Default Mutex Factory                          *
*************************************************/
class BOTAN_DLL Default_Mutex_Factory : public Mutex_Factory
   {
   public:
      Mutex* make();
   };

/*************************************************
* Mutex Holding Class                            *
*************************************************/
class BOTAN_DLL Mutex_Holder
   {
   public:
      Mutex_Holder(Mutex*);
      ~Mutex_Holder();
   private:
      Mutex* mux;
   };

}

#endif
