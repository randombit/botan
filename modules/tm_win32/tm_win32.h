/*************************************************
* Win32 Timer Header File                        *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_EXT_TIMER_WIN32_H__
#define BOTAN_EXT_TIMER_WIN32_H__

#include <botan/timers.h>

namespace Botan {

/*************************************************
* Win32 Timer                                    *
*************************************************/
class Win32_Timer : public Timer
   {
   public:
      u64bit clock() const;
   };

}

#endif
