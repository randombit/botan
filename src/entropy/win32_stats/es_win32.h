/**
* Win32 EntropySource Header File
* (C) 1999-2008 Jack Lloyd
*/

#ifndef BOTAN_ENTROPY_SRC_WIN32_H__
#define BOTAN_ENTROPY_SRC_WIN32_H__

#include <botan/entropy_src.h>

namespace Botan {

/**
* Win32 Entropy Source
*/
class BOTAN_DLL Win32_EntropySource : public EntropySource
   {
   public:
      std::string name() const { return "Win32 Statistics"; }
      void fast_poll(byte buf[], u32bit length);
      void slow_poll(byte buf[], u32bit length);
   };

}

#endif
