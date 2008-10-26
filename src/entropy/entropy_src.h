/*************************************************
* EntropySource Header File                      *
* (C) 2008 Jack Lloyd                            *
*************************************************/

#ifndef BOTAN_ENTROPY_SOURCE_BASE_H__
#define BOTAN_ENTROPY_SOURCE_BASE_H__

#include <botan/types.h>

namespace Botan {

/**
* Abstract interface to a source of (hopefully unpredictable) system entropy
*/
class BOTAN_DLL EntropySource
   {
   public:
      virtual u32bit slow_poll(byte buf[], u32bit len) = 0;
      virtual u32bit fast_poll(byte buf[], u32bit len) = 0;
      virtual ~EntropySource() {}
   };

}

#endif
