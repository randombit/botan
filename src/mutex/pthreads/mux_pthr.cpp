/*
* Pthread Mutex
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/mux_pthr.h>
#include <botan/exceptn.h>

#ifndef _POSIX_C_SOURCE
  #define _POSIX_C_SOURCE 199506
#endif

#include <pthread.h>

namespace Botan {

/*
* Pthread Mutex Factory
*/
Mutex* Pthread_Mutex_Factory::make()
   {

   class Pthread_Mutex : public Mutex
      {
      public:
         void lock()
            {
            if(pthread_mutex_lock(&mutex) != 0)
               throw Invalid_State("Pthread_Mutex::lock: Error occured");
            }

         void unlock()
            {
            if(pthread_mutex_unlock(&mutex) != 0)
               throw Invalid_State("Pthread_Mutex::unlock: Error occured");
            }

         Pthread_Mutex()
            {
            if(pthread_mutex_init(&mutex, 0) != 0)
               throw Invalid_State("Pthread_Mutex: initialization failed");
            }

         ~Pthread_Mutex()
            {
            if(pthread_mutex_destroy(&mutex) != 0)
               throw Invalid_State("~Pthread_Mutex: mutex is still locked");
            }
      private:
         pthread_mutex_t mutex;
      };

   return new Pthread_Mutex();
   }

}
