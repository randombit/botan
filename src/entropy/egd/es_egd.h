/*************************************************
* EGD EntropySource Header File                  *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_ENTROPY_SRC_EGD_H__
#define BOTAN_ENTROPY_SRC_EGD_H__

#include <botan/entropy_src.h>
#include <string>
#include <vector>

namespace Botan {

/*************************************************
* EGD Entropy Source                             *
*************************************************/
class BOTAN_DLL EGD_EntropySource : public EntropySource
   {
   public:
      std::string name() const { return "EGD/PRNGD"; }

      u32bit fast_poll(byte[], u32bit);
      u32bit slow_poll(byte[], u32bit);

      EGD_EntropySource(const std::vector<std::string>& p) : paths(p) {}
   private:
      u32bit do_poll(byte[], u32bit, const std::string&) const;
      const std::vector<std::string> paths;
   };

}

#endif
