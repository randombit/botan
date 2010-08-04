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

/**
* Mutex Base Class
*/
class Mutex
   {
   public:
      /**
      * Lock the mutex
      */
      virtual void lock() = 0;

      /**
      * Unlock the mutex
      */
      virtual void unlock() = 0;
      virtual ~Mutex() {}
   };

/**
* Mutex Factory
*/
class Mutex_Factory
   {
   public:
      /**
      * @return newly allocated mutex
      */
      virtual Mutex* make() = 0;

      virtual ~Mutex_Factory() {}
   };

/**
* Mutex Holding Class for RAII
*/
class Mutex_Holder
   {
   public:
      /**
      * Hold onto a mutex until we leave scope
      * @param m the mutex to lock
      */
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
