/*************************************************
* Device EntropySource Header File               *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_ENTROPY_SRC_DEVICE_H__
#define BOTAN_ENTROPY_SRC_DEVICE_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* Device Based Entropy Source                    *
*************************************************/
class Device_EntropySource : public EntropySource
   {
   public:
      u32bit slow_poll(byte[], u32bit);
   };

}

#endif
