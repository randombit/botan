/*
* High Resolution Timestamp Entropy Source
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ENTROPY_SRC_HRES_TIMER_H__
#define BOTAN_ENTROPY_SRC_HRES_TIMER_H__

#include <botan/entropy_src.h>

namespace Botan {

/**
* Entropy source using high resolution timers
*/
class High_Resolution_Timestamp : public EntropySource
   {
   public:
      std::string name() const { return "High Resolution Timestamp"; }
      void poll(Entropy_Accumulator& accum);
   };

}

#endif
