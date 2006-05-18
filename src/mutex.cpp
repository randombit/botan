/*************************************************
* Mutex Source File                              *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/mutex.h>

namespace Botan {

namespace {

/*************************************************
* Default Mutex                                  *
*************************************************/
class Default_Mutex : public Mutex
   {
   public:
      void lock();
      void unlock();
      Default_Mutex() { locked = false; }
   private:
      bool locked;
   };

/*************************************************
* Lock the mutex                                 *
*************************************************/
void Default_Mutex::lock()
   {
   if(locked)
      throw Internal_Error("Default_Mutex::lock: Mutex is already locked");
   locked = true;
   }

/*************************************************
* Unlock the mutex                               *
*************************************************/
void Default_Mutex::unlock()
   {
   if(!locked)
      throw Internal_Error("Default_Mutex::unlock: Mutex is already unlocked");
   locked = false;
   }

}

/*************************************************
* Mutex_Holder Constructor                       *
*************************************************/
Mutex_Holder::Mutex_Holder(Mutex* m) : mux(m)
   {
   if(!mux)
      throw Invalid_Argument("Mutex_Holder: Argument was NULL");
   mux->lock();
   }

/*************************************************
* Mutex_Holder Destructor                        *
*************************************************/
Mutex_Holder::~Mutex_Holder()
   {
   mux->unlock();
   }

/*************************************************
* Default Mutex Factory                          *
*************************************************/
Mutex* Mutex_Factory::make()
   {
   return new Default_Mutex;
   }

}
