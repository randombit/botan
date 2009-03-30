/*
* Win32 Timer
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_TIMER_WIN32_H__
#define BOTAN_TIMER_WIN32_H__

#include <botan/timer.h>

namespace Botan {

/*
* Win32 Timer
*/
class BOTAN_DLL Win32_Timer : public Timer
   {
   public:
      std::string name() const { return "Win32 QueryPerformanceCounter"; }
      u64bit clock() const;
   };

}

#endif
