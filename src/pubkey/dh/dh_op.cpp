/*************************************************
* DH Operations Source File                      *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/dh_op.h>
#include <botan/eng_def.h>

namespace Botan {

/*************************************************
* Acquire a DH op                                *
*************************************************/
DH_Operation* Default_Engine::dh_op(const DL_Group& group,
                                    const BigInt& x) const
   {
   return new Default_DH_Op(group, x);
   }

}
