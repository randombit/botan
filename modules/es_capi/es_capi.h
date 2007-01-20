/*************************************************
* Win32 CAPI EntropySource Header File           *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_EXT_ENTROPY_SRC_WIN32_CAPI_H__
#define BOTAN_EXT_ENTROPY_SRC_WIN32_CAPI_H__

#include <botan/base.h>
#include <vector>

namespace Botan {

/*************************************************
* Win32 CAPI Entropy Source                      *
*************************************************/
class Win32_CAPI_EntropySource : public EntropySource
   {
   public:
      u32bit slow_poll(byte[], u32bit);
      Win32_CAPI_EntropySource(const std::string& = "");
   private:
      std::vector<u64bit> prov_types;
   };

}

#endif
