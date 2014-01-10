/*
* Entropy Source Using Intel's rdrand instruction
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ENTROPY_SRC_RDRAND_H__
#define BOTAN_ENTROPY_SRC_RDRAND_H__

#include <botan/entropy_src.h>

namespace Botan {

/**
* Entropy source using the rdrand instruction first introduced on
* Intel's Ivy Bridge architecture.
*/
class Intel_Rdrand : public EntropySource
   {
   public:
      std::string name() const { return "Intel Rdrand"; }
      void poll(Entropy_Accumulator& accum);
   };

}

#endif
