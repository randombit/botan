/*************************************************
* Default Engine PK Operations Source File       *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/eng_def.h>
#include <botan/bigintfuncs.h>
#include <botan/reducer.h>
#include <botan/pow_mod.h>
#include <botan/ec_dompar.h>
#include <botan/ecdsa.h>
#include <botan/gfp_element.h>
#ifdef TA_COLL_T
#include <botan/ta.h>
#endif
#include <assert.h>



using namespace Botan::math::ec;

namespace Botan {

namespace {

/*************************************************
* Default IF Operation                           *
*************************************************/
class Default_IF_Op : public IF_Operation
   {
   public:
      BigInt public_op(const BigInt& i) const
         { return powermod_e_n(i); }
      BigInt private_op(const BigInt&) const;

      std::auto_ptr<IF_Operation> clone() const {
    	  return std::auto_ptr<IF_Operation>(new Default_IF_Op(*this));
      }

      Default_IF_Op(const BigInt&, const BigInt&, const BigInt&,
                    const BigInt&, const BigInt&, const BigInt&,
                    const BigInt&, const BigInt&);
   private:
      Fixed_Exponent_Power_Mod powermod_e_n, powermod_d1_p, powermod_d2_q;
      Modular_Reducer reducer;
      BigInt c, q;
   };

/*************************************************
* Default_IF_Op Constructor                      *
*************************************************/
Default_IF_Op::Default_IF_Op(const BigInt& e, const BigInt& n, const BigInt&,
                             const BigInt& p, const BigInt& q,
                             const BigInt& d1, const BigInt& d2,
                             const BigInt& c)
   {
   powermod_e_n = Fixed_Exponent_Power_Mod(e, n);

   if(d1 != 0 && d2 != 0 && p != 0 && q != 0)
      {
      powermod_d1_p = Fixed_Exponent_Power_Mod(d1, p);
      powermod_d2_q = Fixed_Exponent_Power_Mod(d2, q);
      reducer = Modular_Reducer(p);
      this->c = c;
      this->q = q;
      }
   }

/*************************************************
* Default IF Private Operation                   *
*************************************************/
BigInt Default_IF_Op::private_op(const BigInt& i) const
   {
   if(q == 0)
      throw Internal_Error("Default_IF_Op::private_op: No private key");

   BigInt j1 = powermod_d1_p(i);
   BigInt j2 = powermod_d2_q(i);
   j1 = reducer.reduce(sub_mul(j1, j2, c));
   return mul_add(j1, q, j2);
   }

/*************************************************
* Default DSA Operation                          *
*************************************************/
/*
class Default_DSA_Op : public DSA_Operation
   {
   public:
      bool verify(const byte[], u32bit, const byte[], u32bit) const;
      SecureVector<byte> sign(const byte[], u32bit, const BigInt&) const;

      DSA_Operation* clone() const { return new Default_DSA_Op(*this); }

      Default_DSA_Op(const DL_Group&, const BigInt&, const BigInt&);
   private:
      const BigInt x, y;
      const DL_Group group;
      Fixed_Base_Power_Mod powermod_g_p, powermod_y_p;
      Modular_Reducer mod_p, mod_q;
   };
*/
/*************************************************
* Default_DSA_Op Constructor                     *
*************************************************/
/*
Default_DSA_Op::Default_DSA_Op(const DL_Group& grp, const BigInt& y1,
                               const BigInt& x1) : x(x1), y(y1), group(grp)
   {
   powermod_g_p = Fixed_Base_Power_Mod(group.get_g(), group.get_p());
   powermod_y_p = Fixed_Base_Power_Mod(y, group.get_p());
   mod_p = Modular_Reducer(group.get_p());
   mod_q = Modular_Reducer(group.get_q());
   }
*/
/*************************************************
* Default DSA Verify Operation                   *
*************************************************/
/*
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
   s = mod_p.multiply(powermod_g_p(mod_q.multiply(s, i)),
                      powermod_y_p(mod_q.multiply(s, r)));

   return (mod_q.reduce(s) == r);
   }
*/
/*************************************************
* Default DSA Sign Operation                     *
*************************************************/
/*
SecureVector<byte> Default_DSA_Op::sign(const byte in[], u32bit length,
                                        const BigInt& k) const
   {
   if(x == 0)
      throw Internal_Error("Default_DSA_Op::sign: No private key");

   const BigInt& q = group.get_q();
   BigInt i(in, length);

   BigInt r = mod_q.reduce(powermod_g_p(k));
   BigInt s = mod_q.multiply(inverse_mod(k, q), mul_add(x, r, i));

   if(r.is_zero() || s.is_zero())
      throw Internal_Error("Default_DSA_Op::sign: r or s was zero");

   SecureVector<byte> output(2*q.bytes());
   r.binary_encode(output + (output.size() / 2 - r.bytes()));
   s.binary_encode(output + (output.size() - s.bytes()));
   return output;
   }
*/
/*************************************************
* Default NR Operation                           *
*************************************************/
/*
class Default_NR_Op : public NR_Operation
   {
   public:
      SecureVector<byte> verify(const byte[], u32bit) const;
      SecureVector<byte> sign(const byte[], u32bit, const BigInt&) const;

      NR_Operation* clone() const { return new Default_NR_Op(*this); }

      Default_NR_Op(const DL_Group&, const BigInt&, const BigInt&);
   private:
      const BigInt x, y;
      const DL_Group group;
      Fixed_Base_Power_Mod powermod_g_p, powermod_y_p;
      Modular_Reducer mod_p, mod_q;
   };
*/
/*************************************************
* Default_NR_Op Constructor                      *
*************************************************/
/*
Default_NR_Op::Default_NR_Op(const DL_Group& grp, const BigInt& y1,
                             const BigInt& x1) : x(x1), y(y1), group(grp)
   {
   powermod_g_p = Fixed_Base_Power_Mod(group.get_g(), group.get_p());
   powermod_y_p = Fixed_Base_Power_Mod(y, group.get_p());
   mod_p = Modular_Reducer(group.get_p());
   mod_q = Modular_Reducer(group.get_q());
   }
*/
/*************************************************
* Default NR Verify Operation                    *
*************************************************/
/*
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
*/
/*************************************************
* Default NR Sign Operation                      *
*************************************************/
/*
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
*/
/*************************************************
* Default ElGamal Operation                      *
*************************************************/
/*
class Default_ELG_Op : public ELG_Operation
   {
   public:
      SecureVector<byte> encrypt(const byte[], u32bit, const BigInt&) const;
      BigInt decrypt(const BigInt&, const BigInt&) const;

      ELG_Operation* clone() const { return new Default_ELG_Op(*this); }

      Default_ELG_Op(const DL_Group&, const BigInt&, const BigInt&);
   private:
      const BigInt p;
      Fixed_Base_Power_Mod powermod_g_p, powermod_y_p;
      Fixed_Exponent_Power_Mod powermod_x_p;
      Modular_Reducer mod_p;
   };
*/
/*************************************************
* Default_ELG_Op Constructor                     *
*************************************************/
/*
Default_ELG_Op::Default_ELG_Op(const DL_Group& group, const BigInt& y,
                               const BigInt& x) : p(group.get_p())
   {
   powermod_g_p = Fixed_Base_Power_Mod(group.get_g(), p);
   powermod_y_p = Fixed_Base_Power_Mod(y, p);
   mod_p = Modular_Reducer(p);

   if(x != 0)
      powermod_x_p = Fixed_Exponent_Power_Mod(x, p);
   }
*/
/*************************************************
* Default ElGamal Encrypt Operation              *
*************************************************/
/*
SecureVector<byte> Default_ELG_Op::encrypt(const byte in[], u32bit length,
                                           const BigInt& k) const
   {
   BigInt m(in, length);
   if(m >= p)
      throw Invalid_Argument("Default_ELG_Op::encrypt: Input is too large");

   BigInt a = powermod_g_p(k);
   BigInt b = mod_p.multiply(m, powermod_y_p(k));

   SecureVector<byte> output(2*p.bytes());
   a.binary_encode(output + (p.bytes() - a.bytes()));
   b.binary_encode(output + output.size() / 2 + (p.bytes() - b.bytes()));
   return output;
   }
*/
/*************************************************
* Default ElGamal Decrypt Operation              *
*************************************************/
/*
BigInt Default_ELG_Op::decrypt(const BigInt& a, const BigInt& b) const
   {
   if(a >= p || b >= p)
      throw Invalid_Argument("Default_ELG_Op: Invalid message");

   return mod_p.multiply(b, inverse_mod(powermod_x_p(a), p));
   }
*/
/*************************************************
* Default DH Operation                           *
*************************************************/
class Default_DH_Op : public DH_Operation
   {
   public:
      BigInt agree(const BigInt& i) const { return powermod_x_p(i); }
      std::auto_ptr<DH_Operation> clone() const {
    	  return std::auto_ptr<DH_Operation>(new Default_DH_Op(*this));
      }

      Default_DH_Op(const DL_Group& group, const BigInt& x) :
         powermod_x_p(x, group.get_p()) {}
   private:
      const Fixed_Exponent_Power_Mod powermod_x_p;
   };

/*************************************************
* Default ECDSA operation                        *
*************************************************/
class Default_ECDSA_Op : public ECDSA_Operation
    {
    public:
        bool const verify(const byte signature[], u32bit sig_len, const byte message[], u32bit mess_len) const;

        SecureVector<byte> const sign(const byte message[], u32bit mess_len) const;

        std::auto_ptr<ECDSA_Operation> clone() const {
            return std::auto_ptr<ECDSA_Operation>(new Default_ECDSA_Op(*this));
            }

        Default_ECDSA_Op(EC_Domain_Params const& dom_pars, BigInt const& priv_key, PointGFp const& pub_key);
      private:
              Botan::EC_Domain_Params m_dom_pars;
              PointGFp m_pub_key;
              BigInt m_priv_key;

      };

      bool const Default_ECDSA_Op::verify(const byte signature[], u32bit sig_len, const byte message[], u32bit mess_len) const
      {
          //NOTE: it is not checked whether the public point is set
          if(m_dom_pars.get_curve().get_p() == 0)
          {
            throw Internal_Error("domain parameters not set");
          }
          BigInt e(message, mess_len);
          if(sig_len % 2 != 0)
          {
              throw Invalid_Argument("Erroneous length of signature");
          }
          u32bit rs_len = sig_len/2;
          SecureVector<byte> sv_r;
          SecureVector<byte> sv_s;
          sv_r.set(signature, rs_len);
          sv_s.set(signature+rs_len, rs_len);
          BigInt r = BigInt::decode ( sv_r, sv_r.size());
          BigInt s = BigInt::decode (sv_s, sv_s.size());

          if(r < 0 || r >= m_dom_pars.get_order())
          {
           throw Invalid_Argument("r in ECDSA signature has an illegal value");
          }
          if(s < 0 || s >= m_dom_pars.get_order())
          {
              throw Invalid_Argument("s in ECDSA signature has an illegal value");
          }

          BigInt w = inverse_mod(s, m_dom_pars.get_order());
          PointGFp R = w*(e*m_dom_pars.get_base_point() + r*m_pub_key);
          if(R.is_zero())
          {
           return false;
          }
          BigInt x = R.get_affine_x().get_value();
          bool result = (x % m_dom_pars.get_order() == r);
          return result;
      }
      SecureVector<byte> const Default_ECDSA_Op::sign(const byte message[], u32bit mess_len) const
      {
           if(m_priv_key == 0)
           {
               throw Internal_Error("Default_ECDSA_Op::sign(): no private key");
           }
           if(m_dom_pars.get_curve().get_p() == 0)
           {
               throw Internal_Error("Default_ECDSA_Op::sign(): domain parameters not set");
           }

           BigInt e(message, mess_len);

           // generate k
           BigInt k;
           BigInt r(0);
           const BigInt n(m_dom_pars.get_order());
         while(r == 0)
         {
               k = random_integer(1,n);

               PointGFp k_times_P(m_dom_pars.get_base_point());
               k_times_P.mult_this_secure(k, n, n-1);
               k_times_P.check_invariants();
               r =  k_times_P.get_affine_x().get_value() % n;
         }
           BigInt k_inv = inverse_mod(k, n);

           // use randomization against attacks on s:
           // a = k_inv * (r*(d + x) + e) mod n
           // b = k_inv * r * x mod n
           // s = a - b mod n
           // where x is a random integer
           #ifdef CMS_RAND
           BigInt x = Botan::random_integer(0, n);
           BigInt s = m_priv_key + x; // obscure the secret from the beginning
                            // all following operations thus are randomized
           s *= r;
           s += e;
           s *= k_inv;
           s %= n;

           BigInt b = x; // again, start with the random number
           b *= r;
           b *= k_inv;
           b %= n;
           s -= b; // s = a - b
           if(s <= 0) // s %= n
           {
            s += n;
           }
           #else // CMS_RAND
           // no countermeasure here
           BigInt s(r);
           s *= m_priv_key;
           s += e;
           s *= k_inv;
           s %= n;

           #endif // CMS_RAND

           SecureVector<byte> sv_r = BigInt::encode_1363 ( r, m_dom_pars.get_order().bytes() );
           SecureVector<byte> sv_s = BigInt::encode_1363 ( s, m_dom_pars.get_order().bytes() );

           SecureVector<byte> result(sv_r);
           result.append(sv_s);
           return result;
      }
      Default_ECDSA_Op::Default_ECDSA_Op(EC_Domain_Params const& dom_pars, BigInt const& priv_key, PointGFp const& pub_key)
    : m_dom_pars(dom_pars),
      m_pub_key(pub_key),
      m_priv_key(priv_key)
      {

      }

      /*************************************************
      * Default ECKAEG operation                        *
      *************************************************/
         class Default_ECKAEG_Op : public ECKAEG_Operation
         {
         public:
             SecureVector<byte> agree(const PointGFp& i) const;

             std::auto_ptr<ECKAEG_Operation> clone() const {
                return std::auto_ptr<ECKAEG_Operation>(new Default_ECKAEG_Op(*this));
            }

            Default_ECKAEG_Op(EC_Domain_Params const& dom_pars, BigInt const& priv_key, PointGFp const& pub_key);
         private:
             Botan::EC_Domain_Params m_dom_pars;
             PointGFp m_pub_key;
             BigInt m_priv_key;

         };

         Default_ECKAEG_Op::Default_ECKAEG_Op(EC_Domain_Params const& dom_pars, BigInt const& priv_key, PointGFp const& pub_key)
          : m_dom_pars(dom_pars),
            m_pub_key(pub_key),
            m_priv_key(priv_key)
         {

         }
         SecureVector<byte> Default_ECKAEG_Op::agree(const PointGFp& i) const
         {
             BigInt cofactor(m_dom_pars.get_cofactor());
             BigInt n = m_dom_pars.get_order();
             BigInt l(inverse_mod(cofactor,n)); // l=h^-1 mod n
             PointGFp Q(cofactor*i); // q = h*Pb
             PointGFp S(Q);
             BigInt group_order = m_dom_pars.get_cofactor() * n;
             S.mult_this_secure((m_priv_key*l)%n, group_order, n-1);
             S.check_invariants();
             return FE2OSP(S.get_affine_x()); // fe2os(xs)
         }

}

/*************************************************
* Acquire an IF op                               *
*************************************************/
std::tr1::shared_ptr<IF_Operation> Default_Engine::if_op(const BigInt& e, const BigInt& n,
                                    const BigInt& d, const BigInt& p,
                                    const BigInt& q, const BigInt& d1,
                                    const BigInt& d2, const BigInt& c) const
   {
   return std::tr1::shared_ptr<IF_Operation>(new Default_IF_Op(e, n, d, p, q, d1, d2, c));
   }

/*************************************************
* Acquire a DSA op                               *
*************************************************/
/*
DSA_Operation* Default_Engine::dsa_op(const DL_Group& group, const BigInt& y,
                                      const BigInt& x) const
   {
   return new Default_DSA_Op(group, y, x);
   }
*/
/*************************************************
* Acquire a NR op                                *
*************************************************/
/*
NR_Operation* Default_Engine::nr_op(const DL_Group& group, const BigInt& y,
                                    const BigInt& x) const
   {
   return new Default_NR_Op(group, y, x);
   }
*/
/*************************************************
* Acquire an ElGamal op                          *
*************************************************/
/*
ELG_Operation* Default_Engine::elg_op(const DL_Group& group, const BigInt& y,
                                      const BigInt& x) const
   {
   return new Default_ELG_Op(group, y, x);
   }
*/
/*************************************************
* Acquire a DH op                                *
*************************************************/
std::tr1::shared_ptr<DH_Operation> Default_Engine::dh_op(const DL_Group& group,
                                    const BigInt& x) const
   {
   return std::tr1::shared_ptr<DH_Operation>(new Default_DH_Op(group, x));
   }

/*************************************************
* Acquire a ECKAEG op                            *
*************************************************/
std::tr1::shared_ptr<ECKAEG_Operation> Default_Engine::eckaeg_op(EC_Domain_Params const& dom_pars,
        BigInt const& priv_key, PointGFp const& pub_key) const
 {
     return std::tr1::shared_ptr<ECKAEG_Operation>(new Default_ECKAEG_Op(dom_pars,
             priv_key, pub_key));
 }

   std::tr1::shared_ptr<ECDSA_Operation> Default_Engine::ecdsa_op(EC_Domain_Params const& dom_pars,
           BigInt const& priv_key, PointGFp const& pub_key) const
    {
        return std::tr1::shared_ptr<ECDSA_Operation>(new Default_ECDSA_Op(dom_pars,
                priv_key, pub_key));
    }

}
