/*************************************************
* OpenSSL Engine Source File                     *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/eng_ossl.h>
#include <botan/bn_wrap.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x0090700F
  #error Your OpenSSL install is too old, upgrade to 0.9.7 or later
#endif

namespace Botan {

namespace {

/*************************************************
* OpenSSL IF Operation                           *
*************************************************/
class OpenSSL_IF_Op : public IF_Operation
   {
   public:
      BigInt public_op(const BigInt&) const;
      BigInt private_op(const BigInt&) const;

      IF_Operation* clone() const { return new OpenSSL_IF_Op(*this); }

      OpenSSL_IF_Op(const BigInt& e_bn, const BigInt& n_bn, const BigInt&,
                const BigInt& p_bn, const BigInt& q_bn, const BigInt& d1_bn,
                const BigInt& d2_bn, const BigInt& c_bn) :
         e(e_bn), n(n_bn), p(p_bn), q(q_bn), d1(d1_bn), d2(d2_bn), c(c_bn) {}
   private:
      const OSSL_BN e, n, p, q, d1, d2, c;
      OSSL_BN_CTX ctx;
   };

/*************************************************
* OpenSSL IF Public Operation                    *
*************************************************/
BigInt OpenSSL_IF_Op::public_op(const BigInt& i_bn) const
   {
   OSSL_BN i(i_bn), r;
   BN_mod_exp(r.value, i.value, e.value, n.value, ctx.value);
   return r.to_bigint();
   }

/*************************************************
* OpenSSL IF Private Operation                   *
*************************************************/
BigInt OpenSSL_IF_Op::private_op(const BigInt& i_bn) const
   {
   if(BN_is_zero(p.value))
      throw Internal_Error("OpenSSL_IF_Op::private_op: No private key");

   OSSL_BN j1, j2, h(i_bn);

   BN_mod_exp(j1.value, h.value, d1.value, p.value, ctx.value);
   BN_mod_exp(j2.value, h.value, d2.value, q.value, ctx.value);
   BN_sub(h.value, j1.value, j2.value);
   BN_mod_mul(h.value, h.value, c.value, p.value, ctx.value);
   BN_mul(h.value, h.value, q.value, ctx.value);
   BN_add(h.value, h.value, j2.value);
   return h.to_bigint();
   }

/*************************************************
* OpenSSL DSA Operation                          *
*************************************************/
class OpenSSL_DSA_Op : public DSA_Operation
   {
   public:
      bool verify(const byte[], u32bit, const byte[], u32bit) const;
      SecureVector<byte> sign(const byte[], u32bit, const BigInt&) const;

      DSA_Operation* clone() const { return new OpenSSL_DSA_Op(*this); }

      OpenSSL_DSA_Op(const DL_Group& group, const BigInt& y1,
                     const BigInt& x1) :
         x(x1), y(y1), p(group.get_p()), q(group.get_q()), g(group.get_g()) {}
   private:
      const OSSL_BN x, y, p, q, g;
      OSSL_BN_CTX ctx;
   };

/*************************************************
* OpenSSL DSA Verify Operation                   *
*************************************************/
bool OpenSSL_DSA_Op::verify(const byte msg[], u32bit msg_len,
                            const byte sig[], u32bit sig_len) const
   {
   const u32bit q_bytes = q.bytes();

   if(sig_len != 2*q_bytes || msg_len > q_bytes)
      return false;

   OSSL_BN r(sig, q_bytes);
   OSSL_BN s(sig + q_bytes, q_bytes);
   OSSL_BN i(msg, msg_len);

   if(BN_is_zero(r.value) || BN_cmp(r.value, q.value) >= 0)
      return false;
   if(BN_is_zero(s.value) || BN_cmp(s.value, q.value) >= 0)
      return false;

   if(BN_mod_inverse(s.value, s.value, q.value, ctx.value) == 0)
      return false;

   OSSL_BN si;
   BN_mod_mul(si.value, s.value, i.value, q.value, ctx.value);
   BN_mod_exp(si.value, g.value, si.value, p.value, ctx.value);

   OSSL_BN sr;
   BN_mod_mul(sr.value, s.value, r.value, q.value, ctx.value);
   BN_mod_exp(sr.value, y.value, sr.value, p.value, ctx.value);

   BN_mod_mul(si.value, si.value, sr.value, p.value, ctx.value);
   BN_nnmod(si.value, si.value, q.value, ctx.value);

   if(BN_cmp(si.value, r.value) == 0)
      return true;
   return false;
   }

/*************************************************
* OpenSSL DSA Sign Operation                     *
*************************************************/
SecureVector<byte> OpenSSL_DSA_Op::sign(const byte in[], u32bit length,
                                        const BigInt& k_bn) const
   {
   if(BN_is_zero(x.value))
      throw Internal_Error("OpenSSL_DSA_Op::sign: No private key");

   OSSL_BN i(in, length);
   OSSL_BN k(k_bn);

   OSSL_BN r;
   BN_mod_exp(r.value, g.value, k.value, p.value, ctx.value);
   BN_nnmod(r.value, r.value, q.value, ctx.value);

   BN_mod_inverse(k.value, k.value, q.value, ctx.value);

   OSSL_BN s;
   BN_mul(s.value, x.value, r.value, ctx.value);
   BN_add(s.value, s.value, i.value);
   BN_mod_mul(s.value, s.value, k.value, q.value, ctx.value);

   if(BN_is_zero(r.value) || BN_is_zero(s.value))
      throw Internal_Error("OpenSSL_DSA_Op::sign: r or s was zero");

   const u32bit q_bytes = q.bytes();

   SecureVector<byte> output(2*q_bytes);
   r.encode(output, q_bytes);
   s.encode(output + q_bytes, q_bytes);
   return output;
   }

/*************************************************
* OpenSSL NR Operation                           *
*************************************************/
class OpenSSL_NR_Op : public NR_Operation
   {
   public:
      SecureVector<byte> verify(const byte[], u32bit) const;
      SecureVector<byte> sign(const byte[], u32bit, const BigInt&) const;

      NR_Operation* clone() const { return new OpenSSL_NR_Op(*this); }

      OpenSSL_NR_Op(const DL_Group& group, const BigInt& y1,
                    const BigInt& x1) :
         x(x1), y(y1), p(group.get_p()), q(group.get_q()), g(group.get_g()) {}
   private:
      const OSSL_BN x, y, p, q, g;
      OSSL_BN_CTX ctx;
   };

/*************************************************
* OpenSSL NR Verify Operation                    *
*************************************************/
SecureVector<byte> OpenSSL_NR_Op::verify(const byte sig[],
                                         u32bit sig_len) const
   {
   const u32bit q_bytes = q.bytes();

   if(sig_len != 2*q_bytes)
      return false;

   OSSL_BN c(sig, q_bytes);
   OSSL_BN d(sig + q_bytes, q_bytes);

   if(BN_is_zero(c.value) || BN_cmp(c.value, q.value) >= 0 ||
                             BN_cmp(d.value, q.value) >= 0)
      throw Invalid_Argument("OpenSSL_NR_Op::verify: Invalid signature");

   OSSL_BN i1, i2;
   BN_mod_exp(i1.value, g.value, d.value, p.value, ctx.value);
   BN_mod_exp(i2.value, y.value, c.value, p.value, ctx.value);
   BN_mod_mul(i1.value, i1.value, i2.value, p.value, ctx.value);
   BN_sub(i1.value, c.value, i1.value);
   BN_nnmod(i1.value, i1.value, q.value, ctx.value);
   return BigInt::encode(i1.to_bigint());
   }

/*************************************************
* OpenSSL NR Sign Operation                      *
*************************************************/
SecureVector<byte> OpenSSL_NR_Op::sign(const byte in[], u32bit length,
                                       const BigInt& k_bn) const
   {
   if(BN_is_zero(x.value))
      throw Internal_Error("OpenSSL_NR_Op::sign: No private key");

   OSSL_BN f(in, length);
   OSSL_BN k(k_bn);

   if(BN_cmp(f.value, q.value) >= 0)
      throw Invalid_Argument("OpenSSL_NR_Op::sign: Input is out of range");

   OSSL_BN c, d;
   BN_mod_exp(c.value, g.value, k.value, p.value, ctx.value);
   BN_add(c.value, c.value, f.value);
   BN_nnmod(c.value, c.value, q.value, ctx.value);
   BN_mul(d.value, x.value, c.value, ctx.value);
   BN_sub(d.value, k.value, d.value);
   BN_nnmod(d.value, d.value, q.value, ctx.value);

   if(BN_is_zero(c.value))
      throw Internal_Error("Default_NR_Op::sign: c was zero");

   const u32bit q_bytes = q.bytes();
   SecureVector<byte> output(2*q_bytes);
   c.encode(output, q_bytes);
   d.encode(output + q_bytes, q_bytes);
   return output;
   }

/*************************************************
* OpenSSL ElGamal Operation                      *
*************************************************/
class OpenSSL_ELG_Op : public ELG_Operation
   {
   public:
      SecureVector<byte> encrypt(const byte[], u32bit, const BigInt&) const;
      BigInt decrypt(const BigInt&, const BigInt&) const;

      ELG_Operation* clone() const { return new OpenSSL_ELG_Op(*this); }
      OpenSSL_ELG_Op(const DL_Group& group, const BigInt& y1,
                     const BigInt& x1) :
         x(x1), y(y1), g(group.get_g()), p(group.get_p()) {}
   private:
      OSSL_BN x, y, g, p;
      OSSL_BN_CTX ctx;
   };

/*************************************************
* OpenSSL ElGamal Encrypt Operation              *
*************************************************/
SecureVector<byte> OpenSSL_ELG_Op::encrypt(const byte in[], u32bit length,
                                           const BigInt& k_bn) const
   {
   OSSL_BN i(in, length);

   if(BN_cmp(i.value, p.value) >= 0)
      throw Invalid_Argument("OpenSSL_ELG_Op: Input is too large");

   OSSL_BN a, b, k(k_bn);

   BN_mod_exp(a.value, g.value, k.value, p.value, ctx.value);
   BN_mod_exp(b.value, y.value, k.value, p.value, ctx.value);
   BN_mod_mul(b.value, b.value, i.value, p.value, ctx.value);

   const u32bit p_bytes = p.bytes();
   SecureVector<byte> output(2*p_bytes);
   a.encode(output, p_bytes);
   b.encode(output + p_bytes, p_bytes);
   return output;
   }

/*************************************************
* OpenSSL ElGamal Decrypt Operation              *
*************************************************/
BigInt OpenSSL_ELG_Op::decrypt(const BigInt& a_bn, const BigInt& b_bn) const
   {
   if(BN_is_zero(x.value))
      throw Internal_Error("OpenSSL_ELG_Op::decrypt: No private key");

   OSSL_BN a(a_bn), b(b_bn), t;

   if(BN_cmp(a.value, p.value) >= 0 || BN_cmp(b.value, p.value) >= 0)
      throw Invalid_Argument("OpenSSL_ELG_Op: Invalid message");

   BN_mod_exp(t.value, a.value, x.value, p.value, ctx.value);
   BN_mod_inverse(a.value, t.value, p.value, ctx.value);
   BN_mod_mul(a.value, a.value, b.value, p.value, ctx.value);
   return a.to_bigint();
   }

/*************************************************
* OpenSSL DH Operation                           *
*************************************************/
class OpenSSL_DH_Op : public DH_Operation
   {
   public:
      BigInt agree(const BigInt& i) const;
      DH_Operation* clone() const { return new OpenSSL_DH_Op(*this); }

      OpenSSL_DH_Op(const DL_Group& group, const BigInt& x_bn) :
         x(x_bn), p(group.get_p()) {}
   private:
      OSSL_BN x, p;
      OSSL_BN_CTX ctx;
   };

/*************************************************
* OpenSSL DH Key Agreement Operation             *
*************************************************/
BigInt OpenSSL_DH_Op::agree(const BigInt& i_bn) const
   {
   OSSL_BN i(i_bn), r;
   BN_mod_exp(r.value, i.value, x.value, p.value, ctx.value);
   return r.to_bigint();
   }

}

/*************************************************
* Acquire an IF op                               *
*************************************************/
IF_Operation* OpenSSL_Engine::if_op(const BigInt& e, const BigInt& n,
                                    const BigInt& d, const BigInt& p,
                                    const BigInt& q, const BigInt& d1,
                                    const BigInt& d2, const BigInt& c) const
   {
   return new OpenSSL_IF_Op(e, n, d, p, q, d1, d2, c);
   }

/*************************************************
* Acquire a DSA op                               *
*************************************************/
DSA_Operation* OpenSSL_Engine::dsa_op(const DL_Group& group, const BigInt& y,
                                      const BigInt& x) const
   {
   return new OpenSSL_DSA_Op(group, y, x);
   }

/*************************************************
* Acquire a NR op                                *
*************************************************/
NR_Operation* OpenSSL_Engine::nr_op(const DL_Group& group, const BigInt& y,
                                    const BigInt& x) const
   {
   return new OpenSSL_NR_Op(group, y, x);
   }

/*************************************************
* Acquire an ElGamal op                          *
*************************************************/
ELG_Operation* OpenSSL_Engine::elg_op(const DL_Group& group, const BigInt& y,
                                      const BigInt& x) const
   {
   return new OpenSSL_ELG_Op(group, y, x);
   }

/*************************************************
* Acquire a DH op                                *
*************************************************/
DH_Operation* OpenSSL_Engine::dh_op(const DL_Group& group,
                                    const BigInt& x) const
   {
   return new OpenSSL_DH_Op(group, x);
   }

}
