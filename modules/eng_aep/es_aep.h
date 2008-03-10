/*************************************************
* AEP EntropySource Header File                  *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_EXT_ENTROPY_SRC_AEP_H__
#define BOTAN_EXT_ENTROPY_SRC_AEP_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* AEP Entropy Source                             *
*************************************************/
class AEP_EntropySource : public EntropySource
   {
   public:
      u32bit slow_poll(byte[], u32bit);
   };

}

#endif
