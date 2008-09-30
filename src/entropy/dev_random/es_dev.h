/*************************************************
* Device EntropySource Header File               *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_ENTROPY_SRC_DEVICE_H__
#define BOTAN_ENTROPY_SRC_DEVICE_H__

#include <botan/rng.h>
#include <vector>

namespace Botan {

/*************************************************
* Device Based Entropy Source                    *
*************************************************/
class Device_EntropySource : public EntropySource
   {
   public:
      Device_EntropySource(const std::vector<std::string>& fs) : fsnames(fs) {}
      u32bit slow_poll(byte[], u32bit);
   private:
      std::vector<std::string> fsnames;
   };

}

#endif
