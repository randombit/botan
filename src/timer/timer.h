/**
* Timestamp Functions
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_TIMERS_H__
#define BOTAN_TIMERS_H__

#include <botan/rng.h>
#include <ctime>

namespace Botan {

/*
* Time Access/Conversion Functions
*/
BOTAN_DLL u64bit system_time();

BOTAN_DLL std::tm time_t_to_tm(u64bit);

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

      void poll(Entropy_Accumulator& accum);

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
