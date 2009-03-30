/*
* Mutex
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MUTEX_H__
#define BOTAN_MUTEX_H__

#include <botan/exceptn.h>

namespace Botan {

/*
* Mutex Base Class
*/
class BOTAN_DLL Mutex
   {
   public:
      virtual void lock() = 0;
      virtual void unlock() = 0;
      virtual ~Mutex() {}
   };

/*
* Mutex Factory
*/
class BOTAN_DLL Mutex_Factory
   {
   public:
      virtual Mutex* make() = 0;
      virtual ~Mutex_Factory() {}
   };

/*
* Mutex Holding Class
*/
class BOTAN_DLL Mutex_Holder
   {
   public:
      Mutex_Holder(Mutex* m) : mux(m)
         {
         if(!mux)
            throw Invalid_Argument("Mutex_Holder: Argument was NULL");
         mux->lock();
         }

      ~Mutex_Holder() { mux->unlock(); }
   private:
      Mutex* mux;
   };

}

#endif
