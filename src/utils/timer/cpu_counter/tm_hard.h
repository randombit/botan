/*************************************************
* Hardware Timer Header File                     *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_TIMER_HARDWARE_H__
#define BOTAN_TIMER_HARDWARE_H__

#include <botan/timers.h>

namespace Botan {

/*************************************************
* Hardware Timer                                 *
*************************************************/
class BOTAN_DLL Hardware_Timer : public Timer
   {
   public:
      std::string name() const { return "Hardware Timer"; }
      u64bit clock() const;
   };

}

#endif
