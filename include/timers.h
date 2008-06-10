/*************************************************
* Timestamp Functions Header File                *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_TIMERS_H__
#define BOTAN_TIMERS_H__

#include <botan/rng.h>

namespace Botan {

/*************************************************
* Timer Interface                                *
*************************************************/
class BOTAN_DLL Timer : public EntropySource
   {
   public:
      virtual u64bit clock() const;
      u32bit slow_poll(byte[], u32bit);

      virtual ~Timer() {}
   protected:
      static u64bit combine_timers(u32bit, u32bit, u32bit);
   };

}

#endif
