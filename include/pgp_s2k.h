/*************************************************
* OpenPGP S2K Header File                        *
* (C) 1999-2008 The Botan Project                *
*************************************************/

#ifndef BOTAN_OPENPGP_S2K_H__
#define BOTAN_OPENPGP_S2K_H__

#include <botan/s2k.h>

namespace Botan {

/*************************************************
* OpenPGP S2K                                    *
*************************************************/
class OpenPGP_S2K : public S2K
   {
   public:
      std::string name() const;
      S2K* clone() const;
      OpenPGP_S2K(const std::string&);
   private:
      OctetString derive(u32bit, const std::string&,
                         const byte[], u32bit, u32bit) const;
      const std::string hash_name;
   };

}

#endif
