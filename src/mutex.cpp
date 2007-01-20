/*************************************************
* Mutex Source File                              *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/mutex.h>
#include <botan/libstate.h>

namespace Botan {

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
* Named_Mutex_Holder Constructor                 *
*************************************************/
Named_Mutex_Holder::Named_Mutex_Holder(const std::string& name) :
   mutex_name(name)
   {
   global_state().get_named_mutex(mutex_name)->lock();
   }

/*************************************************
* Named_Mutex_Holder Destructor                  *
*************************************************/
Named_Mutex_Holder::~Named_Mutex_Holder()
   {
   global_state().get_named_mutex(mutex_name)->unlock();
   }

/*************************************************
* Default Mutex Factory                          *
*************************************************/
Mutex* Default_Mutex_Factory::make()
   {
   class Default_Mutex : public Mutex
      {
      public:
         class Mutex_State_Error : public Internal_Error
            {
            public:
               Mutex_State_Error(const std::string& where) :
                  Internal_Error("Default_Mutex::" + where + ": " +
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

         Default_Mutex() { locked = false; }
      private:
         bool locked;
      };

   return new Default_Mutex;
   }

}
