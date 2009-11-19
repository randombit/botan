/*
* POSIX Timer
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_TIMER_POSIX_H__
#define BOTAN_TIMER_POSIX_H__

#include <botan/timer.h>

namespace Botan {

/*
* POSIX Timer
*/
class BOTAN_DLL POSIX_Timer : public Timer
   {
   public:
      std::string name() const { return "POSIX clock_gettime"; }
      u64bit clock() const;
   };

}

#endif
