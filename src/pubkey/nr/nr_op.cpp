/*
* NR Operations
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/nr_op.h>

namespace Botan {

/*
* Default_NR_Op Constructor
*/
Default_NR_Op::Default_NR_Op(const DL_Group& grp, const BigInt& y1,
                             const BigInt& x1) : x(x1), y(y1), group(grp)
   {
   powermod_g_p = Fixed_Base_Power_Mod(group.get_g(), group.get_p());
   powermod_y_p = Fixed_Base_Power_Mod(y, group.get_p());
   mod_p = Modular_Reducer(group.get_p());
   mod_q = Modular_Reducer(group.get_q());
   }

/*
* Default NR Verify Operation
*/
SecureVector<byte> Default_NR_Op::verify(const byte in[], u32bit length) const
   {
   const BigInt& q = group.get_q();

   if(length != 2*q.bytes())
      return false;

   BigInt c(in, q.bytes());
   BigInt d(in + q.bytes(), q.bytes());

   if(c.is_zero() || c >= q || d >= q)
      throw Invalid_Argument("Default_NR_Op::verify: Invalid signature");

   BigInt i = mod_p.multiply(powermod_g_p(d), powermod_y_p(c));
   return BigInt::encode(mod_q.reduce(c - i));
   }

/*
* Default NR Sign Operation
*/
SecureVector<byte> Default_NR_Op::sign(const byte in[], u32bit length,
                                       const BigInt& k) const
   {
   if(x == 0)
      throw Internal_Error("Default_NR_Op::sign: No private key");

   const BigInt& q = group.get_q();

   BigInt f(in, length);

   if(f >= q)
      throw Invalid_Argument("Default_NR_Op::sign: Input is out of range");

   BigInt c = mod_q.reduce(powermod_g_p(k) + f);
   if(c.is_zero())
      throw Internal_Error("Default_NR_Op::sign: c was zero");
   BigInt d = mod_q.reduce(k - x * c);

   SecureVector<byte> output(2*q.bytes());
   c.binary_encode(output + (output.size() / 2 - c.bytes()));
   d.binary_encode(output + (output.size() - d.bytes()));
   return output;
   }

}
