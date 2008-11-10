/*************************************************
* Block Cipher Padding Lookup                    *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/def_eng.h>
#include <botan/scan_name.h>

#if defined(BOTAN_HAS_CIPHER_MODE_PADDING)
  #include <botan/mode_pad.h>
#endif

namespace Botan {

/*************************************************
* Look for an algorithm with this name           *
*************************************************/
BlockCipherModePaddingMethod*
Default_Engine::find_bc_pad(const std::string& algo_spec) const
   {
   SCAN_Name request(algo_spec);

#if defined(BOTAN_HAS_CIPHER_MODE_PADDING)
   if(request.algo_name() == "PKCS7")
      return new PKCS7_Padding;

   if(request.algo_name() == "OneAndZeros")
      return new OneAndZeros_Padding;

   if(request.algo_name() == "X9.23")
      return new ANSI_X923_Padding;

   if(request.algo_name() == "NoPadding")
      return new Null_Padding;
#endif

   return 0;
   }

}
