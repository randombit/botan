/*************************************************
* Win32 Mutex Source File                        *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/mux_win32.h>
#include <botan/exceptn.h>
#include <windows.h>

namespace Botan {

namespace {

/*************************************************
* Win32 Mutex                                    *
*************************************************/
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

}

/*************************************************
* Win32 Mutex Factory                            *
*************************************************/
Mutex* Win32_Mutex_Factory::make()
   {
   return new Win32_Mutex();
   }

}
