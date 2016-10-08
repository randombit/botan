/**
 * XMSS Tools
 * Contains some helper functions.
 * (C) 2016 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/
#include <botan/xmss_tools.h>

namespace Botan {

XMSS_Tools::XMSS_Tools()
   {
#if defined(BOTAN_TARGET_CPU_HAS_KNOWN_ENDIANESS)
#if defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
           m_is_little_endian = true;
#else
           m_is_little_endian = false;
#endif
#else
       uint16_t data = 0x01;
       m_is_little_endian = reinterpret_cast<const byte*>(&data)[0] == 0x01;
#endif
   }

const XMSS_Tools& XMSS_Tools::get()
   {
   static const XMSS_Tools self;
   return self;
   }

}
