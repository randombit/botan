/*
* No-Op Mutex Factory
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/mux_noop.h>

namespace Botan {

/*
* No-Op Mutex Factory
*/
Mutex* Noop_Mutex_Factory::make()
   {
   class Noop_Mutex : public Mutex
      {
      public:
         class Mutex_State_Error : public Internal_Error
            {
            public:
               Mutex_State_Error(const std::string& where) :
                  Internal_Error("Noop_Mutex::" + where + ": " +
                                 "Mutex is already " + where + "ed") {}
            };

         void lock()
            {
            if(locked)
               throw Mutex_State_Error("lock");
            locked = true;
            }

         void unlock()
            {
            if(!locked)
               throw Mutex_State_Error("unlock");
            locked = false;
            }

         Noop_Mutex() { locked = false; }
      private:
         bool locked;
      };

   return new Noop_Mutex;
   }

}
