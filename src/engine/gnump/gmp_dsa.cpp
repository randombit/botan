/*
* GMP DSA Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eng_gmp.h>
#include <botan/gmp_wrap.h>
#include <gmp.h>

namespace Botan {

#if defined(BOTAN_HAS_DSA)

namespace {

/*
* GMP DSA Operation
*/
class GMP_DSA_Op : public DSA_Operation
   {
   public:
      bool verify(const byte[], u32bit, const byte[], u32bit) const;
      SecureVector<byte> sign(const byte[], u32bit, const BigInt&) const;

      DSA_Operation* clone() const { return new GMP_DSA_Op(*this); }

      GMP_DSA_Op(const DL_Group& group, const BigInt& y1, const BigInt& x1) :
         x(x1), y(y1), p(group.get_p()), q(group.get_q()), g(group.get_g()) {}
   private:
      const GMP_MPZ x, y, p, q, g;
   };

/*
* GMP DSA Verify Operation
*/
bool GMP_DSA_Op::verify(const byte msg[], u32bit msg_len,
                        const byte sig[], u32bit sig_len) const
   {
   const u32bit q_bytes = q.bytes();

   if(sig_len != 2*q_bytes || msg_len > q_bytes)
      return false;

   GMP_MPZ r(sig, q_bytes);
   GMP_MPZ s(sig + q_bytes, q_bytes);
   GMP_MPZ i(msg, msg_len);

   if(mpz_cmp_ui(r.value, 0) <= 0 || mpz_cmp(r.value, q.value) >= 0)
      return false;
   if(mpz_cmp_ui(s.value, 0) <= 0 || mpz_cmp(s.value, q.value) >= 0)
      return false;

   if(mpz_invert(s.value, s.value, q.value) == 0)
      return false;

   GMP_MPZ si;
   mpz_mul(si.value, s.value, i.value);
   mpz_mod(si.value, si.value, q.value);
   mpz_powm(si.value, g.value, si.value, p.value);

   GMP_MPZ sr;
   mpz_mul(sr.value, s.value, r.value);
   mpz_mod(sr.value, sr.value, q.value);
   mpz_powm(sr.value, y.value, sr.value, p.value);

   mpz_mul(si.value, si.value, sr.value);
   mpz_mod(si.value, si.value, p.value);
   mpz_mod(si.value, si.value, q.value);

   if(mpz_cmp(si.value, r.value) == 0)
      return true;
   return false;
   }

/*
* GMP DSA Sign Operation
*/
SecureVector<byte> GMP_DSA_Op::sign(const byte in[], u32bit length,
                                    const BigInt& k_bn) const
   {
   if(mpz_cmp_ui(x.value, 0) == 0)
      throw Internal_Error("GMP_DSA_Op::sign: No private key");

   GMP_MPZ i(in, length);
   GMP_MPZ k(k_bn);

   GMP_MPZ r;
   mpz_powm(r.value, g.value, k.value, p.value);
   mpz_mod(r.value, r.value, q.value);

   mpz_invert(k.value, k.value, q.value);

   GMP_MPZ s;
   mpz_mul(s.value, x.value, r.value);
   mpz_add(s.value, s.value, i.value);
   mpz_mul(s.value, s.value, k.value);
   mpz_mod(s.value, s.value, q.value);

   if(mpz_cmp_ui(r.value, 0) == 0 || mpz_cmp_ui(s.value, 0) == 0)
      throw Internal_Error("GMP_DSA_Op::sign: r or s was zero");

   const u32bit q_bytes = q.bytes();

   SecureVector<byte> output(2*q_bytes);
   r.encode(output, q_bytes);
   s.encode(output + q_bytes, q_bytes);
   return output;
   }

}

/*
* Acquire a DSA op
*/
DSA_Operation* GMP_Engine::dsa_op(const DL_Group& group, const BigInt& y,
                                  const BigInt& x) const
   {
   return new GMP_DSA_Op(group, y, x);
   }
#endif

}
