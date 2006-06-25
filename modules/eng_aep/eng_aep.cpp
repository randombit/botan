/*************************************************
* AEP Engine Source File                         *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/eng_aep.h>
#include <botan/numthry.h>

namespace Botan {

namespace {

/*************************************************
* AEP IF Operation                               *
*************************************************/
class AEP_IF_Op : public IF_Operation
   {
   public:
      BigInt public_op(const BigInt&) const;
      BigInt private_op(const BigInt&) const;

      IF_Operation* clone() const { return new AEP_IF_Op(*this); }

      AEP_IF_Op(const BigInt&, const BigInt&, const BigInt&,
                const BigInt&, const BigInt&, const BigInt&,
                const BigInt&, const BigInt&);
   private:
      const BigInt e, n, p, q, d1, d2, c;
   };

/*************************************************
* AEP_IF_Op Constructor                          *
*************************************************/
AEP_IF_Op::AEP_IF_Op(const BigInt& ex, const BigInt& nx, const BigInt&,
                     const BigInt& px, const BigInt& qx,
                     const BigInt& d1x, const BigInt& d2x,
                     const BigInt& cx) :
   e(ex), n(nx), p(px), q(qx), d1(d1x), d2(d2x), c(cx)
   {
   }

/*************************************************
* AEP IF Public Operation                        *
*************************************************/
BigInt AEP_IF_Op::public_op(const BigInt& i) const
   {
   return AEP_Engine::pow_mod(i, e, n);
   }

/*************************************************
* AEP IF Private Operation                       *
*************************************************/
BigInt AEP_IF_Op::private_op(const BigInt& i) const
   {
   if(p == 0 || q == 0)
      throw Internal_Error("AEP_IF_Op::private_op: No private key");

   return AEP_Engine::pow_mod_crt(i, n, p, q, d1, d2, c);
   }

/*************************************************
* AEP DSA Operation                              *
*************************************************/
class AEP_DSA_Op : public DSA_Operation
   {
   public:
      bool verify(const byte[], u32bit, const byte[], u32bit) const;
      SecureVector<byte> sign(const byte[], u32bit, const BigInt&) const;

      DSA_Operation* clone() const { return new AEP_DSA_Op(*this); }

      AEP_DSA_Op(const DL_Group&, const BigInt&, const BigInt&);
   private:
      const BigInt x, y;
      const DL_Group group;
      Modular_Reducer mod_p, mod_q;
   };

/*************************************************
* AEP_DSA_Op Constructor                         *
*************************************************/
AEP_DSA_Op::AEP_DSA_Op(const DL_Group& grp, const BigInt& y1,
                       const BigInt& x1) : x(x1), y(y1), group(grp)
   {
   mod_p = Modular_Reducer(group.get_p());
   mod_q = Modular_Reducer(group.get_q());
   }

/*************************************************
* AEP DSA Verify Operation                       *
*************************************************/
bool AEP_DSA_Op::verify(const byte msg[], u32bit msg_len,
                        const byte sig[], u32bit sig_len) const
   {
   const BigInt& g = group.get_g();
   const BigInt& q = group.get_q();
   const BigInt& p = group.get_p();

   if(sig_len != 2*q.bytes() || msg_len > q.bytes())
      return false;

   BigInt r(sig, q.bytes());
   BigInt s(sig + q.bytes(), q.bytes());
   BigInt i(msg, msg_len);

   if(r <= 0 || r >= q || s <= 0 || s >= q)
      return false;

   s = inverse_mod(s, q);
   s = mod_p.multiply(AEP_Engine::pow_mod(g, mod_q.multiply(s, i), p),
                      AEP_Engine::pow_mod(y, mod_q.multiply(s, r), p));

   return (s % q == r);
   }

/*************************************************
* AEP DSA Sign Operation                         *
*************************************************/
SecureVector<byte> AEP_DSA_Op::sign(const byte in[], u32bit length,
                                    const BigInt& k) const
   {
   if(x == 0)
      throw Internal_Error("AEP_DSA_Op::sign: No private key");

   const BigInt& g = group.get_g();
   const BigInt& q = group.get_q();
   const BigInt& p = group.get_p();
   BigInt i(in, length);

   BigInt r = AEP_Engine::pow_mod(g, k, p) % q;
   BigInt s = mod_q.multiply(inverse_mod(k, q), mul_add(x, r, i));
   if(r.is_zero() || s.is_zero())
      throw Internal_Error("AEP_DSA_Op::sign: r or s was zero");

   SecureVector<byte> output(2*q.bytes());
   r.binary_encode(output + (output.size() / 2 - r.bytes()));
   s.binary_encode(output + (output.size() - s.bytes()));
   return output;
   }

/*************************************************
* AEP NR Operation                               *
*************************************************/
class AEP_NR_Op : public NR_Operation
   {
   public:
      SecureVector<byte> verify(const byte[], u32bit) const;
      SecureVector<byte> sign(const byte[], u32bit, const BigInt&) const;

      NR_Operation* clone() const { return new AEP_NR_Op(*this); }

      AEP_NR_Op(const DL_Group&, const BigInt&, const BigInt&);
   private:
      const BigInt x, y;
      const DL_Group group;
      Modular_Reducer mod_p;
   };

/*************************************************
* AEP_NR_Op Constructor                          *
*************************************************/
AEP_NR_Op::AEP_NR_Op(const DL_Group& grp, const BigInt& y1,
                     const BigInt& x1) : x(x1), y(y1), group(grp)
   {
   mod_p = Modular_Reducer(group.get_p());
   }

/*************************************************
* AEP NR Verify Operation                        *
*************************************************/
SecureVector<byte> AEP_NR_Op::verify(const byte in[], u32bit length) const
   {
   const BigInt& g = group.get_g();
   const BigInt& q = group.get_q();
   const BigInt& p = group.get_p();

   if(length != 2*q.bytes())
      return false;

   BigInt c(in, q.bytes());
   BigInt d(in + q.bytes(), q.bytes());

   if(c.is_zero() || c >= q || d >= q)
      throw Invalid_Argument("AEP_NR_Op::verify: Invalid signature");

   BigInt i = mod_p.multiply(AEP_Engine::pow_mod(g, d, p),
                             AEP_Engine::pow_mod(y, c, p));
   return BigInt::encode((c - i) % q);
   }

/*************************************************
* AEP NR Sign Operation                          *
*************************************************/
SecureVector<byte> AEP_NR_Op::sign(const byte in[], u32bit length,
                                   const BigInt& k) const
   {
   if(x == 0)
      throw Internal_Error("AEP_NR_Op::sign: No private key");

   const BigInt& g = group.get_g();
   const BigInt& q = group.get_q();
   const BigInt& p = group.get_p();

   BigInt f(in, length);

   if(f >= q)
      throw Invalid_Argument("AEP_NR_Op::sign: Input is out of range");

   BigInt c = (AEP_Engine::pow_mod(g, k, p) + f) % q;
   if(c.is_zero())
      throw Internal_Error("AEP_NR_Op::sign: c was zero");
   BigInt d = (k - x * c) % q;

   SecureVector<byte> output(2*q.bytes());
   c.binary_encode(output + (output.size() / 2 - c.bytes()));
   d.binary_encode(output + (output.size() - d.bytes()));
   return output;
   }

/*************************************************
* AEP ElGamal Operation                          *
*************************************************/
class AEP_ELG_Op : public ELG_Operation
   {
   public:
      SecureVector<byte> encrypt(const byte[], u32bit, const BigInt&) const;
      BigInt decrypt(const BigInt&, const BigInt&) const;

      ELG_Operation* clone() const { return new AEP_ELG_Op(*this); }

      AEP_ELG_Op(const DL_Group&, const BigInt&, const BigInt&);
   private:
      const BigInt x, y;
      const DL_Group group;
      Modular_Reducer mod_p;
   };

/*************************************************
* AEP_ELG_Op Constructor                         *
*************************************************/
AEP_ELG_Op::AEP_ELG_Op(const DL_Group& grp, const BigInt& y1,
                       const BigInt& x1) : x(x1), y(y1), group(grp)
   {
   mod_p = Modular_Reducer(group.get_p());
   }

/*************************************************
* AEP ElGamal Encrypt Operation                  *
*************************************************/
SecureVector<byte> AEP_ELG_Op::encrypt(const byte in[], u32bit length,
                                       const BigInt& k) const
   {
   const BigInt& g = group.get_g();
   const BigInt& p = group.get_p();

   BigInt m(in, length);
   if(m >= p)
      throw Invalid_Argument("AEP_ELG_Op::encrypt: Input is too large");

   BigInt a = AEP_Engine::pow_mod(g, k, p);
   BigInt b = mod_p.multiply(m, AEP_Engine::pow_mod(y, k, p));

   SecureVector<byte> output(2*p.bytes());
   a.binary_encode(output + (p.bytes() - a.bytes()));
   b.binary_encode(output + output.size() / 2 + (p.bytes() - b.bytes()));
   return output;
   }

/*************************************************
* AEP ElGamal Decrypt Operation                  *
*************************************************/
BigInt AEP_ELG_Op::decrypt(const BigInt& a, const BigInt& b) const
   {
   if(x == 0)
      throw Internal_Error("AEP_ELG_Op::decrypt: No private key");

   const BigInt& p = group.get_p();

   if(a >= p || b >= p)
      throw Invalid_Argument("AEP_ELG_Op: Invalid message");

   return mod_p.multiply(b, inverse_mod(AEP_Engine::pow_mod(a, x, p), p));
   }

/*************************************************
* AEP DH Operation                               *
*************************************************/
class AEP_DH_Op : public DH_Operation
   {
   public:
      BigInt agree(const BigInt& i) const
         { return AEP_Engine::pow_mod(i, x, p); }
      DH_Operation* clone() const { return new AEP_DH_Op(*this); }

      AEP_DH_Op(const DL_Group& group, const BigInt& x1) :
         x(x1), p(group.get_p()) {}
   private:
      const BigInt x, p;
   };

}

/*************************************************
* Acquire an IF op                               *
*************************************************/
IF_Operation* AEP_Engine::if_op(const BigInt& e, const BigInt& n,
                                const BigInt& d, const BigInt& p,
                                const BigInt& q, const BigInt& d1,
                                const BigInt& d2, const BigInt& c) const
   {
   if(AEP_Engine::ok_to_use(n))
      return new AEP_IF_Op(e, n, d, p, q, d1, d2, c);
   return 0;
   }

/*************************************************
* Acquire a DSA op                               *
*************************************************/
DSA_Operation* AEP_Engine::dsa_op(const DL_Group& group, const BigInt& y,
                                  const BigInt& x) const
   {
   if(AEP_Engine::ok_to_use(group.get_p()))
      return new AEP_DSA_Op(group, y, x);
   return 0;
   }

/*************************************************
* Acquire a NR op                                *
*************************************************/
NR_Operation* AEP_Engine::nr_op(const DL_Group& group, const BigInt& y,
                                const BigInt& x) const
   {
   if(AEP_Engine::ok_to_use(group.get_p()))
      return new AEP_NR_Op(group, y, x);
   return 0;
   }

/*************************************************
* Acquire an ElGamal op                          *
*************************************************/
ELG_Operation* AEP_Engine::elg_op(const DL_Group& group, const BigInt& y,
                                  const BigInt& x) const
   {
   if(AEP_Engine::ok_to_use(group.get_p()))
      return new AEP_ELG_Op(group, y, x);
   return 0;
   }

/*************************************************
* Acquire a DH op                                *
*************************************************/
DH_Operation* AEP_Engine::dh_op(const DL_Group& group, const BigInt& x) const
   {
   if(AEP_Engine::ok_to_use(group.get_p()))
      return new AEP_DH_Op(group, x);
   return 0;
   }

}
