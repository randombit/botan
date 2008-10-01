/*************************************************
* IF Operations Header File                      *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_IF_OP_H__
#define BOTAN_IF_OP_H__

#include <botan/bigint.h>

namespace Botan {

/*************************************************
* IF Operation                                   *
*************************************************/
class BOTAN_DLL IF_Operation
   {
   public:
      virtual BigInt public_op(const BigInt&) const = 0;
      virtual BigInt private_op(const BigInt&) const = 0;
      virtual IF_Operation* clone() const = 0;
      virtual ~IF_Operation() {}
   };

}

#endif
