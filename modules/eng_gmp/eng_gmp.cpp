/*************************************************
* GMP Engine Source File                         *
* (C) 1999-2008 The Botan Project                *
*************************************************/

#include <botan/eng_gmp.h>
#include <botan/gmp_wrap.h>
#include <gmp.h>

namespace Botan {

namespace {

/*************************************************
* GMP IF Operation                               *
*************************************************/
class GMP_IF_Op : public IF_Operation
   {
   public:
      BigInt public_op(const BigInt&) const;
      BigInt private_op(const BigInt&) const;

      IF_Operation* clone() const { return new GMP_IF_Op(*this); }

      GMP_IF_Op(const BigInt& e_bn, const BigInt& n_bn, const BigInt&,
                const BigInt& p_bn, const BigInt& q_bn, const BigInt& d1_bn,
                const BigInt& d2_bn, const BigInt& c_bn) :
         e(e_bn), n(n_bn), p(p_bn), q(q_bn), d1(d1_bn), d2(d2_bn), c(c_bn) {}
   private:
      const GMP_MPZ e, n, p, q, d1, d2, c;
   };

/*************************************************
* GMP IF Public Operation                        *
*************************************************/
BigInt GMP_IF_Op::public_op(const BigInt& i_bn) const
   {
   GMP_MPZ i(i_bn);
   mpz_powm(i.value, i.value, e.value, n.value);
   return i.to_bigint();
   }

/*************************************************
* GMP IF Private Operation                       *
*************************************************/
BigInt GMP_IF_Op::private_op(const BigInt& i_bn) const
   {
   if(mpz_cmp_ui(p.value, 0) == 0)
      throw Internal_Error("GMP_IF_Op::private_op: No private key");

   GMP_MPZ j1, j2, h(i_bn);

   mpz_powm(j1.value, h.value, d1.value, p.value);
   mpz_powm(j2.value, h.value, d2.value, q.value);
   mpz_sub(h.value, j1.value, j2.value);
   mpz_mul(h.value, h.value, c.value);
   mpz_mod(h.value, h.value, p.value);
   mpz_mul(h.value, h.value, q.value);
   mpz_add(h.value, h.value, j2.value);
   return h.to_bigint();
   }

/*************************************************
* GMP DSA Operation                              *
*************************************************/
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

/*************************************************
* GMP DSA Verify Operation                       *
*************************************************/
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

/*************************************************
* GMP DSA Sign Operation                         *
*************************************************/
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

/*************************************************
* GMP NR Operation                               *
*************************************************/
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

/*************************************************
* GMP NR Verify Operation                        *
*************************************************/
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

/*************************************************
* GMP NR Sign Operation                          *
*************************************************/
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

/*************************************************
* GMP ElGamal Operation                          *
*************************************************/
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

/*************************************************
* GMP ElGamal Encrypt Operation                  *
*************************************************/
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

/*************************************************
* GMP ElGamal Decrypt Operation                  *
*************************************************/
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

/*************************************************
* GMP DH Operation                               *
*************************************************/
class GMP_DH_Op : public DH_Operation
   {
   public:
      BigInt agree(const BigInt& i) const;
      DH_Operation* clone() const { return new GMP_DH_Op(*this); }

      GMP_DH_Op(const DL_Group& group, const BigInt& x_bn) :
         x(x_bn), p(group.get_p()) {}
   private:
      GMP_MPZ x, p;
   };

/*************************************************
* GMP DH Key Agreement Operation                 *
*************************************************/
BigInt GMP_DH_Op::agree(const BigInt& i_bn) const
   {
   GMP_MPZ i(i_bn);
   mpz_powm(i.value, i.value, x.value, p.value);
   return i.to_bigint();
   }

}

/*************************************************
* GMP_Engine Constructor                         *
*************************************************/
GMP_Engine::GMP_Engine()
   {
   set_memory_hooks();
   }

/*************************************************
* Acquire an IF op                               *
*************************************************/
IF_Operation* GMP_Engine::if_op(const BigInt& e, const BigInt& n,
                                const BigInt& d, const BigInt& p,
                                const BigInt& q, const BigInt& d1,
                                const BigInt& d2, const BigInt& c) const
   {
   return new GMP_IF_Op(e, n, d, p, q, d1, d2, c);
   }

/*************************************************
* Acquire a DSA op                               *
*************************************************/
DSA_Operation* GMP_Engine::dsa_op(const DL_Group& group, const BigInt& y,
                                  const BigInt& x) const
   {
   return new GMP_DSA_Op(group, y, x);
   }

/*************************************************
* Acquire a NR op                                *
*************************************************/
NR_Operation* GMP_Engine::nr_op(const DL_Group& group, const BigInt& y,
                                const BigInt& x) const
   {
   return new GMP_NR_Op(group, y, x);
   }

/*************************************************
* Acquire an ElGamal op                          *
*************************************************/
ELG_Operation* GMP_Engine::elg_op(const DL_Group& group, const BigInt& y,
                                  const BigInt& x) const
   {
   return new GMP_ELG_Op(group, y, x);
   }

/*************************************************
* Acquire a DH op                                *
*************************************************/
DH_Operation* GMP_Engine::dh_op(const DL_Group& group, const BigInt& x) const
   {
   return new GMP_DH_Op(group, x);
   }

}
