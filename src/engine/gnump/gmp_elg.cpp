/*
* GMP ElGamal Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eng_gmp.h>
#include <botan/gmp_wrap.h>
#include <gmp.h>

namespace Botan {

#if defined(BOTAN_HAS_ELGAMAL)

namespace {

/*
* GMP ElGamal Operation
*/
class GMP_ELG_Op : public ELG_Operation
   {
   public:
      SecureVector<byte> encrypt(const byte[], u32bit, const BigInt&) const;
      BigInt decrypt(const BigInt&, const BigInt&) const;

      ELG_Operation* clone() const { return new GMP_ELG_Op(*this); }

      GMP_ELG_Op(const DL_Group& group, const BigInt& y1, const BigInt& x1) :
         x(x1), y(y1), g(group.get_g()), p(group.get_p()) {}
   private:
      GMP_MPZ x, y, g, p;
   };

/*
* GMP ElGamal Encrypt Operation
*/
SecureVector<byte> GMP_ELG_Op::encrypt(const byte in[], u32bit length,
                                       const BigInt& k_bn) const
   {
   GMP_MPZ i(in, length);

   if(mpz_cmp(i.value, p.value) >= 0)
      throw Invalid_Argument("GMP_ELG_Op: Input is too large");

   GMP_MPZ a, b, k(k_bn);

   mpz_powm(a.value, g.value, k.value, p.value);
   mpz_powm(b.value, y.value, k.value, p.value);
   mpz_mul(b.value, b.value, i.value);
   mpz_mod(b.value, b.value, p.value);

   const u32bit p_bytes = p.bytes();
   SecureVector<byte> output(2*p_bytes);
   a.encode(output, p_bytes);
   b.encode(output + p_bytes, p_bytes);
   return output;
   }

/*
* GMP ElGamal Decrypt Operation
*/
BigInt GMP_ELG_Op::decrypt(const BigInt& a_bn, const BigInt& b_bn) const
   {
   if(mpz_cmp_ui(x.value, 0) == 0)
      throw Internal_Error("GMP_ELG_Op::decrypt: No private key");

   GMP_MPZ a(a_bn), b(b_bn);

   if(mpz_cmp(a.value, p.value) >= 0 || mpz_cmp(b.value, p.value) >= 0)
      throw Invalid_Argument("GMP_ELG_Op: Invalid message");

   mpz_powm(a.value, a.value, x.value, p.value);
   mpz_invert(a.value, a.value, p.value);
   mpz_mul(a.value, a.value, b.value);
   mpz_mod(a.value, a.value, p.value);
   return a.to_bigint();
   }

}

/*
* Acquire an ElGamal op
*/
ELG_Operation* GMP_Engine::elg_op(const DL_Group& group, const BigInt& y,
                                  const BigInt& x) const
   {
   return new GMP_ELG_Op(group, y, x);
   }
#endif

}
