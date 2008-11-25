/**
* Timestamp Functions Header File
* (C) 1999-2008 Jack Lloyd
*/

#ifndef BOTAN_TIMERS_H__
#define BOTAN_TIMERS_H__

#include <botan/rng.h>

namespace Botan {

/**
* Timer Interface
*/
class BOTAN_DLL Timer : public EntropySource
   {
   public:
      /**
      @return nanoseconds resolution timestamp, unknown epoch
      */
      virtual u64bit clock() const = 0;

      u32bit slow_poll(byte[], u32bit);
      u32bit fast_poll(byte[], u32bit);

      virtual ~Timer() {}
   protected:
      static u64bit combine_timers(u32bit, u32bit, u32bit);
   };

/**
* ANSI Clock Timer
*/
class BOTAN_DLL ANSI_Clock_Timer : public Timer
   {
   public:
      std::string name() const { return "ANSI clock"; }
      u64bit clock() const;
   };

}

#endif
