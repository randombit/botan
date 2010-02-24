/*
* DSA Operations
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/dsa_op.h>
#include <future>

namespace Botan {

/*
* Default_DSA_Op Constructor
*/
Default_DSA_Op::Default_DSA_Op(const DL_Group& grp, const BigInt& y1,
                               const BigInt& x1) : x(x1), y(y1), group(grp)
   {
   powermod_g_p = Fixed_Base_Power_Mod(group.get_g(), group.get_p());
   powermod_y_p = Fixed_Base_Power_Mod(y, group.get_p());
   mod_p = Modular_Reducer(group.get_p());
   mod_q = Modular_Reducer(group.get_q());
   }

/*
* Default DSA Verify Operation
*/
bool Default_DSA_Op::verify(const byte msg[], u32bit msg_len,
                            const byte sig[], u32bit sig_len) const
   {
   const BigInt& q = group.get_q();

   if(sig_len != 2*q.bytes() || msg_len > q.bytes())
      return false;

   BigInt r(sig, q.bytes());
   BigInt s(sig + q.bytes(), q.bytes());
   BigInt i(msg, msg_len);

   if(r <= 0 || r >= q || s <= 0 || s >= q)
      return false;

   s = inverse_mod(s, q);

   auto future_s_i = std::async(std::launch::async,
      [&]() { return powermod_g_p(mod_q.multiply(s, i)); });

   BigInt s_r = powermod_y_p(mod_q.multiply(s, r));
   BigInt s_i = future_s_i.get();

   s = mod_p.multiply(s_i, s_r);

   return (mod_q.reduce(s) == r);
   }

/*
* Default DSA Sign Operation
*/
SecureVector<byte> Default_DSA_Op::sign(const byte in[], u32bit length,
                                        const BigInt& k) const
   {
   if(x == 0)
      throw Internal_Error("Default_DSA_Op::sign: No private key");

   auto future_r = std::async(std::launch::async,
                              [&]() { return mod_q.reduce(powermod_g_p(k)); });

   const BigInt& q = group.get_q();
   BigInt i(in, length);

   BigInt s = inverse_mod(k, q);
   BigInt r = future_r.get();

   s = mod_q.multiply(s, mul_add(x, r, i));

   if(r.is_zero() || s.is_zero())
      throw Internal_Error("Default_DSA_Op::sign: r or s was zero");

   SecureVector<byte> output(2*q.bytes());
   r.binary_encode(output + (output.size() / 2 - r.bytes()));
   s.binary_encode(output + (output.size() - s.bytes()));
   return output;
   }

}
