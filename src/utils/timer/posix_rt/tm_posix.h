/*************************************************
* POSIX Timer Header File                        *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_TIMER_POSIX_H__
#define BOTAN_TIMER_POSIX_H__

#include <botan/timers.h>

namespace Botan {

/*************************************************
* POSIX Timer                                    *
*************************************************/
class BOTAN_DLL POSIX_Timer : public Timer
   {
   public:
      std::string name() const { return "POSIX clock_gettime"; }
      u64bit clock() const;
   };

}

#endif
