/*************************************************
* Unix Timer Header File                         *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_EXT_TIMER_UNIX_H__
#define BOTAN_EXT_TIMER_UNIX_H__

#include <botan/timers.h>

namespace Botan {

/*************************************************
* Unix Timer                                     *
*************************************************/
class Unix_Timer : public Timer
   {
   public:
      u64bit clock() const;
   };

}

#endif
