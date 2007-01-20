/*************************************************
* MGF1 Header File                               *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_MGF1_H__
#define BOTAN_MGF1_H__

#include <botan/pk_util.h>

namespace Botan {

/*************************************************
* MGF1                                           *
*************************************************/
class MGF1 : public MGF
   {
   public:
      void mask(const byte[], u32bit, byte[], u32bit) const;
      MGF1(const std::string&);
   private:
      const std::string hash_name;
   };

}

#endif
