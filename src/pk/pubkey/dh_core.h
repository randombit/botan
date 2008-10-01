/*************************************************
* DH Core Header File                            *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_DH_CORE_H__
#define BOTAN_DH_CORE_H__

#include <botan/bigint.h>
#include <botan/blinding.h>
#include <botan/pk_ops.h>
#include <botan/dl_group.h>

namespace Botan {

/*************************************************
* DH Core                                        *
*************************************************/
class BOTAN_DLL DH_Core
   {
   public:
      BigInt agree(const BigInt&) const;

      DH_Core& operator=(const DH_Core&);

      DH_Core() { op = 0; }
      DH_Core(const DH_Core&);
      DH_Core(RandomNumberGenerator& rng,
              const DL_Group&, const BigInt&);
      ~DH_Core() { delete op; }
   private:
      DH_Operation* op;
      Blinder blinder;
   };

}

#endif
