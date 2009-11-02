/*
* Win32 Timer
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/tm_win32.h>
#include <windows.h>

namespace Botan {

/*
* Get the timestamp
*/
u64bit Win32_Timer::clock() const
   {
   LARGE_INTEGER tv;
   ::QueryPerformanceCounter(&tv);
   return tv.QuadPart;
   }

}
