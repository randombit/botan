/*
* Unix Timer
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_TIMER_UNIX_H__
#define BOTAN_TIMER_UNIX_H__

#include <botan/timer.h>

namespace Botan {

/*
* Unix Timer
*/
class BOTAN_DLL Unix_Timer : public Timer
   {
   public:
      std::string name() const { return "Unix gettimeofday"; }
      u64bit clock() const;
   };

}

#endif
