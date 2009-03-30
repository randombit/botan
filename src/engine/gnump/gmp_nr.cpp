/*
* GMP NR Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eng_gmp.h>
#include <botan/gmp_wrap.h>
#include <gmp.h>

namespace Botan {

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)

namespace {

/*
* GMP NR Operation
*/
class GMP_NR_Op : public NR_Operation
   {
   public:
      SecureVector<byte> verify(const byte[], u32bit) const;
      SecureVector<byte> sign(const byte[], u32bit, const BigInt&) const;

      NR_Operation* clone() const { return new GMP_NR_Op(*this); }

      GMP_NR_Op(const DL_Group& group, const BigInt& y1, const BigInt& x1) :
         x(x1), y(y1), p(group.get_p()), q(group.get_q()), g(group.get_g()) {}
   private:
      const GMP_MPZ x, y, p, q, g;
   };

/*
* GMP NR Verify Operation
*/
SecureVector<byte> GMP_NR_Op::verify(const byte sig[], u32bit sig_len) const
   {
   const u32bit q_bytes = q.bytes();

   if(sig_len != 2*q_bytes)
      return false;

   GMP_MPZ c(sig, q_bytes);
   GMP_MPZ d(sig + q_bytes, q_bytes);

   if(mpz_cmp_ui(c.value, 0) <= 0 || mpz_cmp(c.value, q.value) >= 0 ||
                                     mpz_cmp(d.value, q.value) >= 0)
      throw Invalid_Argument("GMP_NR_Op::verify: Invalid signature");

   GMP_MPZ i1, i2;
   mpz_powm(i1.value, g.value, d.value, p.value);
   mpz_powm(i2.value, y.value, c.value, p.value);
   mpz_mul(i1.value, i1.value, i2.value);
   mpz_mod(i1.value, i1.value, p.value);
   mpz_sub(i1.value, c.value, i1.value);
   mpz_mod(i1.value, i1.value, q.value);
   return BigInt::encode(i1.to_bigint());
   }

/*
* GMP NR Sign Operation
*/
SecureVector<byte> GMP_NR_Op::sign(const byte in[], u32bit length,
                                    const BigInt& k_bn) const
   {
   if(mpz_cmp_ui(x.value, 0) == 0)
      throw Internal_Error("GMP_NR_Op::sign: No private key");

   GMP_MPZ f(in, length);
   GMP_MPZ k(k_bn);

   if(mpz_cmp(f.value, q.value) >= 0)
      throw Invalid_Argument("GMP_NR_Op::sign: Input is out of range");

   GMP_MPZ c, d;
   mpz_powm(c.value, g.value, k.value, p.value);
   mpz_add(c.value, c.value, f.value);
   mpz_mod(c.value, c.value, q.value);
   mpz_mul(d.value, x.value, c.value);
   mpz_sub(d.value, k.value, d.value);
   mpz_mod(d.value, d.value, q.value);

   if(mpz_cmp_ui(c.value, 0) == 0)
      throw Internal_Error("Default_NR_Op::sign: c was zero");

   const u32bit q_bytes = q.bytes();
   SecureVector<byte> output(2*q_bytes);
   c.encode(output, q_bytes);
   d.encode(output + q_bytes, q_bytes);
   return output;
   }

}

/*
* Acquire a NR op
*/
NR_Operation* GMP_Engine::nr_op(const DL_Group& group, const BigInt& y,
                                const BigInt& x) const
   {
   return new GMP_NR_Op(group, y, x);
   }
#endif

}
