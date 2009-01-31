/**
* BeOS EntropySource Header File
* (C) 1999-2008 Jack Lloyd
*/

#ifndef BOTAN_ENTROPY_SRC_BEOS_H__
#define BOTAN_ENTROPY_SRC_BEOS_H__

#include <botan/entropy_src.h>

namespace Botan {

/**
* BeOS Entropy Source
*/
class BOTAN_DLL BeOS_EntropySource : public EntropySource
   {
   private:
      std::string name() const { return "BeOS Statistics"; }

      void poll(Entropy_Accumulator& accum);
   };

}

#endif
