/*************************************************
* Win32 CAPI EntropySource Header File           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_ENTROPY_SRC_WIN32_CAPI_H__
#define BOTAN_ENTROPY_SRC_WIN32_CAPI_H__

#include <botan/entropy_src.h>
#include <vector>

namespace Botan {

/*************************************************
* Win32 CAPI Entropy Source                      *
*************************************************/
class BOTAN_DLL Win32_CAPI_EntropySource : public EntropySource
   {
   public:
      u32bit slow_poll(byte[], u32bit);
      Win32_CAPI_EntropySource(const std::string& = "");
   private:
      std::vector<u64bit> prov_types;
   };

}

#endif
