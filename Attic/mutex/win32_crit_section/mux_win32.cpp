/*
* Win32 Mutex
* (C) 2006 Luca Piccarreta
*     2006-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/mux_win32.h>
#include <windows.h>

namespace Botan {

/*
* Win32 Mutex Factory
*/
Mutex* Win32_Mutex_Factory::make()
   {
   class Win32_Mutex : public Mutex
      {
      public:
         void lock() { EnterCriticalSection(&mutex); }
         void unlock() { LeaveCriticalSection(&mutex); }

         Win32_Mutex() { InitializeCriticalSection(&mutex); }
         ~Win32_Mutex() { DeleteCriticalSection(&mutex); }
      private:
         CRITICAL_SECTION mutex;
      };

   return new Win32_Mutex();
   }

}
