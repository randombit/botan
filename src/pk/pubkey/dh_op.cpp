/*************************************************
* DH Operations Source File                      *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/eng_def.h>
#include <botan/pow_mod.h>
#include <botan/numthry.h>
#include <botan/reducer.h>

namespace Botan {

namespace {

/*************************************************
* Default DH Operation                           *
*************************************************/
class Default_DH_Op : public DH_Operation
   {
   public:
      BigInt agree(const BigInt& i) const { return powermod_x_p(i); }
      DH_Operation* clone() const { return new Default_DH_Op(*this); }

      Default_DH_Op(const DL_Group& group, const BigInt& x) :
         powermod_x_p(x, group.get_p()) {}
   private:
      const Fixed_Exponent_Power_Mod powermod_x_p;
   };

}

/*************************************************
* Acquire a DH op                                *
*************************************************/
DH_Operation* Default_Engine::dh_op(const DL_Group& group,
                                    const BigInt& x) const
   {
   return new Default_DH_Op(group, x);
   }

}
