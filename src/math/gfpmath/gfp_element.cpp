/******
 * Arithmetic for prime fields GF(p) (source file)
 *
 * (C) 2007 Martin Doering
 *          doering@cdc.informatik.tu-darmstadt.de
 *          Christoph Ludwig
 *          ludwig@fh-worms.de
 *          Falko Strenzke
 *          strenzke@flexsecure.de
 ******/

#include <botan/gfp_element.h>
#include <botan/numthry.h>
#include <botan/def_powm.h>
#include <botan/mp_types.h>
#include <botan/mp_asm.h>
#include <botan/mp_asmi.h>
#include <assert.h>
#include <ostream>

namespace Botan {

namespace {

void inner_montg_mult_sos(word result[], const word* a_bar, const word* b_bar, const word* n, const word* n_dash, u32bit s)
   {
   SecureVector<word> t;
   t.grow_to(2*s+1);

   // t = a_bar * b_bar
   for (u32bit i=0; i<s; i++)
      {
      word C = 0;
      word S = 0;
      for (u32bit j=0; j<s; j++)
         {
         // we use:
         // word word_madd3(word a, word b, word c, word d, word* carry)
         // returns a * b + c + d and resets the carry (not using it as input)

         S = word_madd3(a_bar[j], b_bar[i], t[i+j], &C);
         t[i+j] = S;
         }
      t[i+s] = C;
      }

   // ???
   for (u32bit i=0; i<s; i++)
      {
      // word word_madd2(word a, word b, word c, word* carry)
      // returns a * b + c, resets the carry

      word C = 0;
      word zero = 0;
      word m = word_madd2(t[i], n_dash[0], &zero);

      for (u32bit j=0; j<s; j++)
         {
         word S = word_madd3(m, n[j], t[i+j], &C);
         t[i+j] = S;
         }

      //// mp_mulop.cpp:
      ////word bigint_mul_add_words(word z[], const word x[], u32bit x_size, word y)
      u32bit cnt = 0;
      while (C > 0)
         {
         // we need not worry here about C > 1, because the other operand is zero
         word tmp = word_add(t[i+s+cnt], 0, &C);
         t[i+s+cnt] = tmp;
         cnt++;
         }
      }

   // u = t
   SecureVector<word> u;
   u.grow_to(s+1);
   for (u32bit j=0; j<s+1; j++)
      {
      u[j] = t[j+s];
      }

   // t = u - n
   word B = 0;
   word D = 0;
   for (u32bit i=0; i<s; i++)
      {
      D = word_sub(u[i], n[i], &B);
      t[i] = D;
      }
   D = word_sub(u[s], 0, &B);
   t[s] = D;

   // if t >= 0 (B == 0 -> no borrow), return t
   if(B == 0)
      {
      for (u32bit i=0; i<s; i++)
         {
         result[i] = t[i];
         }
      }
   else // else return u
      {
      for (u32bit i=0; i<s; i++)
         {
         result[i] = u[i];
         }
      }
   }

void montg_mult(BigInt& result, BigInt& a_bar, BigInt& b_bar, const BigInt& m, const BigInt& m_dash, const BigInt)
   {
   if(m.is_zero() || m_dash.is_zero())
      throw Invalid_Argument("montg_mult(): neither modulus nor m_dash may be zero (and one of them was)");

   if(a_bar.is_zero() || b_bar.is_zero())
      result = 0;

   u32bit s = m.sig_words();
   a_bar.grow_to(s);
   b_bar.grow_to(s);
   result.grow_to(s);

   inner_montg_mult_sos(result.get_reg(), a_bar.data(), b_bar.data(),
                        m.data(), m_dash.data(), s);
   }

/**
*calculates R=b^n (here b=2) with R>m (and R beeing as small as possible) for an odd modulus m.
* no check for oddity is performed!
*
* Distributed under the terms of the Botan license
*/
BigInt montgm_calc_r_oddmod(const BigInt& prime)
   {
   u32bit n = prime.sig_words();
   BigInt result(1);
   result <<= n*BOTAN_MP_WORD_BITS;
   return result;
   }

/**
*calculates m' with r*r^-1 - m*m' = 1
* where r^-1 is the multiplicative inverse of r to the modulus m
*/
BigInt montgm_calc_m_dash(const BigInt& r, const BigInt& m, const BigInt& r_inv)
   {
   BigInt result = ((r * r_inv) - BigInt(1))/m;
   return result;
   }

BigInt montg_trf_to_mres(const BigInt& ord_res, const BigInt& r, const BigInt& m)
   {
   BigInt result(ord_res);
   result *= r;
   result %= m;
   return result;
   }

BigInt montg_trf_to_ordres(const BigInt& m_res, const BigInt& m, const BigInt& r_inv)
   {
   BigInt result(m_res);
   result *= r_inv;
   result %= m;
   return result;
   }

}

GFpElement::GFpElement(const BigInt& p, const BigInt& value, bool use_montgm)
   : mp_mod(),
     m_value(value %p),
     m_use_montgm(use_montgm),
     m_is_trf(false)
   {
   assert(mp_mod.get() == 0);
   mp_mod = std::tr1::shared_ptr<GFpModulus>(new GFpModulus(p));
   assert(mp_mod->m_p_dash == 0);
   if(m_use_montgm)
      ensure_montgm_precomp();
   }

GFpElement::GFpElement(std::tr1::shared_ptr<GFpModulus> const mod, const BigInt& value, bool use_montgm)
   : mp_mod(),
     m_value(value % mod->m_p),
     m_use_montgm(use_montgm),
     m_is_trf(false)
   {
   assert(mp_mod.get() == 0);
   mp_mod = mod;
   }

GFpElement::GFpElement(const GFpElement& other)
   : m_value(other.m_value),
     m_use_montgm(other.m_use_montgm),
     m_is_trf(other.m_is_trf)

   {
   //creates an independent copy
   assert((other.m_is_trf && other.m_use_montgm) || !other.m_is_trf);
   mp_mod.reset(new GFpModulus(*other.mp_mod)); // copy-ctor of GFpModulus
   }

void GFpElement::turn_on_sp_red_mul() const
   {
   ensure_montgm_precomp();
   m_use_montgm = true;
   }

void GFpElement::turn_off_sp_red_mul() const
   {
   if(m_is_trf)
      {
      trf_to_ordres();
      // will happen soon anyway, so we can do it here already
      // (this is not lazy but way more secure concerning our internal logic here)
      }
   m_use_montgm = false;
   }

void GFpElement::ensure_montgm_precomp() const
   {
   if((!mp_mod->m_r.is_zero()) && (!mp_mod->m_r_inv.is_zero()) && (!mp_mod->m_p_dash.is_zero()))
      {
      // values are already set, nothing more to do
      }
   else
      {
      BigInt tmp_r(montgm_calc_r_oddmod(mp_mod->m_p));

      BigInt tmp_r_inv(inverse_mod(tmp_r, mp_mod->m_p));

      BigInt tmp_p_dash(montgm_calc_m_dash(tmp_r, mp_mod->m_p, tmp_r_inv));

      mp_mod->m_r.grow_reg(tmp_r.size());
      mp_mod->m_r_inv.grow_reg(tmp_r_inv.size());
      mp_mod->m_p_dash.grow_reg(tmp_p_dash.size());

      mp_mod->m_r = tmp_r;
      mp_mod->m_r_inv = tmp_r_inv;
      mp_mod->m_p_dash = tmp_p_dash;

      assert(!mp_mod->m_r.is_zero());
      assert(!mp_mod->m_r_inv.is_zero());
      assert(!mp_mod->m_p_dash.is_zero());
      }

   }

void GFpElement::set_shrd_mod(std::tr1::shared_ptr<GFpModulus> const p_mod)
   {
   mp_mod = p_mod;
   }

void GFpElement::trf_to_mres() const
   {
   if(!m_use_montgm)
      {
      throw Illegal_Transformation("GFpElement is not allowed to be transformed to m-residue");
      }
   assert(m_is_trf == false);
   assert(!mp_mod->m_r_inv.is_zero());
   assert(!mp_mod->m_p_dash.is_zero());
   m_value = montg_trf_to_mres(m_value, mp_mod->m_r, mp_mod->m_p);
   m_is_trf = true;
   }

void GFpElement::trf_to_ordres() const
   {
   assert(m_is_trf == true);
   m_value = montg_trf_to_ordres(m_value, mp_mod->m_p, mp_mod->m_r_inv);
   m_is_trf = false;
   }

bool GFpElement::align_operands_res(const GFpElement& lhs, const GFpElement& rhs) //static
   {
   assert(lhs.mp_mod->m_p == rhs.mp_mod->m_p);
   if(lhs.m_use_montgm && rhs.m_use_montgm)
      {
      assert(rhs.mp_mod->m_p_dash == lhs.mp_mod->m_p_dash);
      assert(rhs.mp_mod->m_r == lhs.mp_mod->m_r);
      assert(rhs.mp_mod->m_r_inv == lhs.mp_mod->m_r_inv);
      if(!lhs.m_is_trf && !rhs.m_is_trf)
         {
         return false;
         }
      else if(lhs.m_is_trf && rhs.m_is_trf)
         {
         return true;
         }
      else // one is transf., the other not
         {
         if(!lhs.m_is_trf)
            {
            lhs.trf_to_mres();
            assert(rhs.m_is_trf==true);
            return true;
            }
         assert(rhs.m_is_trf==false);
         assert(lhs.m_is_trf==true);
         rhs.trf_to_mres(); // the only possibility left...
         return true;
         }
      }
   else // at least one of them does not use mm
      // (so it is impossible that both use it)
      {
      if(lhs.m_is_trf)
         {
         lhs.trf_to_ordres();
         assert(rhs.m_is_trf == false);
         return false;
         }
      if(rhs.m_is_trf)
         {
         rhs.trf_to_ordres();
         assert(lhs.m_is_trf == false);
         return false;
         }
      return false;
      }
   assert(false);
   }

bool GFpElement::is_trf_to_mres() const
   {
   return m_is_trf;
   }

const BigInt& GFpElement::get_p() const
   {
   return (mp_mod->m_p);
   }

const BigInt& GFpElement::get_value() const
   {
   if(m_is_trf)
      {
      assert(m_use_montgm);
      trf_to_ordres();
      }
   return m_value;
   }

const BigInt& GFpElement::get_mres() const
   {
   if(!m_use_montgm)
      {
      // does the following exception really make sense?
      // wouldn´t it be better to simply turn on montg.mult. when
      // this explicit request is made?
      throw Illegal_Transformation("GFpElement is not allowed to be transformed to m-residue");
      }
   if(!m_is_trf)
      {
      trf_to_mres();
      }

   return m_value;
   }

const GFpElement& GFpElement::operator=(const GFpElement& other)
   {
   m_value.grow_reg(other.m_value.size()); // grow first for exception safety

   //m_value = other.m_value;

   //              m_use_montgm = other.m_use_montgm;
   //              m_is_trf = other.m_is_trf;
   // we want to keep the member pointers, which might be part of a "sharing group"
   // but we may not simply overwrite the BigInt values with those of the argument!!
   // if ours already contains precomputations, it would be hazardous to
   // set them back to zero.
   // thus we first check for equality of the moduli,
   // then whether either of the two objects already contains
   // precomputed values.

   // we also deal with the case were the pointers themsevles are equal:
   if(mp_mod.get() == other.mp_mod.get())
      {
      // everything ok, we are in the same sharing group anyway, nothing to do
      m_value = other.m_value; // cannot throw
      m_use_montgm = other.m_use_montgm;
      m_is_trf = other.m_is_trf;
      return *this;
      }
   if(mp_mod->m_p != other.mp_mod->m_p)
      {
      // the moduli are different, this is a special case
      // which will not occur in usual applications,
      // so we don´t hesitate to simply create new objects
      // (we do want to create an independent copy)
      mp_mod.reset(new GFpModulus(*other.mp_mod)); // this could throw,
      // and because of this
      // we haven't modified
      // anything so far
      m_value = other.m_value; // can't throw
      m_use_montgm = other.m_use_montgm;
      m_is_trf = other.m_is_trf;
      return *this;
      }
   // exception safety note: from now on we are on the safe
   // side with respect to the modulus,
   // so we can assign the value now:
   m_value = other.m_value;
   m_use_montgm = other.m_use_montgm;
   m_is_trf = other.m_is_trf;
   // the moduli are equal, but we deal with different sharing groups.
   // we will NOT fuse the sharing goups
   // and we will NOT reset already precomputed values
   if(mp_mod->has_precomputations())
      {
      // our own sharing group already has precomputed values,
      // so nothing to do.
      return *this;
      }
   else
      {
      // let´s see whether the argument has something for us...
      if(other.mp_mod->has_precomputations())
         {
         // fetch them for our sharing group
         // exc. safety note: grow first
         mp_mod->m_p_dash.grow_reg(other.mp_mod->m_p_dash.size());
         mp_mod->m_r.grow_reg(other.mp_mod->m_r.size());
         mp_mod->m_r_inv.grow_reg(other.mp_mod->m_r_inv.size());

         mp_mod->m_p_dash = other.mp_mod->m_p_dash;
         mp_mod->m_r = other.mp_mod->m_r;
         mp_mod->m_r_inv = other.mp_mod->m_r_inv;
         return *this;
         }
      }
   // our precomputations aren´t set, the arguments neither,
   // so we let them alone
   return *this;
   }

void GFpElement::share_assign(const GFpElement& other)
   {
   assert((other.m_is_trf && other.m_use_montgm) || !other.m_is_trf);

   // use grow_to to make it exc safe
   m_value.grow_reg(other.m_value.size());
   m_value = other.m_value;

   m_use_montgm = other.m_use_montgm;
   m_is_trf = other.m_is_trf;
   mp_mod = other.mp_mod; // cannot throw
   }

GFpElement& GFpElement::operator+=(const GFpElement& rhs)
   {
   GFpElement::align_operands_res(*this, rhs);

   workspace = m_value;
   workspace += rhs.m_value;
   if(workspace >= mp_mod->m_p)
      workspace -= mp_mod->m_p;

   m_value = workspace;
   assert(m_value < mp_mod->m_p);
   assert(m_value >= 0);

   return *this;
   }

GFpElement& GFpElement::operator-=(const GFpElement& rhs)
   {
   GFpElement::align_operands_res(*this, rhs);

   workspace = m_value;

   workspace -= rhs.m_value;

   if(workspace.is_negative())
      workspace += mp_mod->m_p;

   m_value = workspace;
   assert(m_value < mp_mod->m_p);
   assert(m_value >= 0);
   return *this;
   }

GFpElement& GFpElement::operator*= (u32bit rhs)
   {
   workspace = m_value;
   workspace *= rhs;
   workspace %= mp_mod->m_p;
   m_value = workspace;
   return *this;
   }

GFpElement& GFpElement::operator*=(const GFpElement& rhs)
   {
   assert(rhs.mp_mod->m_p == mp_mod->m_p);
   // here, we do not use align_operands_res() for one simple reason:
   // we want to enforce the transformation to an m-residue, otherwise it would
  // never happen
   if(m_use_montgm && rhs.m_use_montgm)
      {
      assert(rhs.mp_mod->m_p == mp_mod->m_p); // is montgm. mult is on, then precomps must be there
      assert(rhs.mp_mod->m_p_dash == mp_mod->m_p_dash);
      assert(rhs.mp_mod->m_r == mp_mod->m_r);
      if(!m_is_trf)
         {
         trf_to_mres();
         }
      if(!rhs.m_is_trf)
         {
         rhs.trf_to_mres();
         }
      workspace = m_value;
      montg_mult(m_value, workspace, rhs.m_value, mp_mod->m_p, mp_mod->m_p_dash, mp_mod->m_r);
      }
   else // ordinary multiplication
      {
      if(m_is_trf)
         {
         assert(m_use_montgm);
         trf_to_ordres();
         }
      if(rhs.m_is_trf)
         {
         assert(rhs.m_use_montgm);
         rhs.trf_to_ordres();
         }

      workspace = m_value;
      workspace *= rhs.m_value;
      workspace %= mp_mod->m_p;
      m_value = workspace;
      }
   return *this;
   }

GFpElement& GFpElement::operator/=(const GFpElement& rhs)
   {
   bool use_mres = GFpElement::align_operands_res(*this, rhs);
   assert((this->m_is_trf && rhs.m_is_trf) || !(this->m_is_trf && rhs.m_is_trf));
   // (internal note: see C86)
   if(use_mres)
      {
      assert(m_use_montgm && rhs.m_use_montgm);
      GFpElement rhs_ordres(rhs);
      rhs_ordres.trf_to_ordres();
      rhs_ordres.inverse_in_place();
      workspace = m_value;
      workspace *=  rhs_ordres.get_value();
      workspace %= mp_mod->m_p;
      m_value = workspace;

      }
   else
      {
      GFpElement inv_rhs(rhs);
      inv_rhs.inverse_in_place();
      *this *= inv_rhs;
      }
   return *this;
   }

bool GFpElement::is_zero()
   {
   return (m_value.is_zero());
   // this is correct because x_bar = x * r = x = 0 for x = 0
   }

GFpElement& GFpElement::inverse_in_place()
   {
   m_value = inverse_mod(m_value, mp_mod->m_p);
   if(m_is_trf)
      {
      assert(m_use_montgm);

      m_value *= mp_mod->m_r;
      m_value *= mp_mod->m_r;
      m_value %= mp_mod->m_p;
      }
   assert(m_value <= mp_mod->m_p);
   return *this;
   }

GFpElement& GFpElement::negate()
   {
   m_value = mp_mod->m_p - m_value;
   assert(m_value <= mp_mod->m_p);
   return *this;
   }

void GFpElement::swap(GFpElement& other)
   {
   m_value.swap(other.m_value);
   mp_mod.swap(other.mp_mod);
   std::swap<bool>(m_use_montgm,other.m_use_montgm);
   std::swap<bool>(m_is_trf,other.m_is_trf);
   }

std::ostream& operator<<(std::ostream& output, const GFpElement& elem)
   {
   return output << '(' << elem.get_value() << "," << elem.get_p() << ')';
   }

bool operator==(const GFpElement& lhs, const GFpElement& rhs)
   {
   // for effeciency reasons we firstly check whether
   //the modulus pointers are different in the first place:
   if(lhs.get_ptr_mod() != rhs.get_ptr_mod())
      {
      if(lhs.get_p() != rhs.get_p())
         {
         return false;
         }
      }
   // so the modulus is equal, now check the values
   bool use_mres = GFpElement::align_operands_res(lhs, rhs);

   if(use_mres)
      {
      return (lhs.get_mres() == rhs.get_mres());
      }
   else
      {
      return(lhs.get_value() == rhs.get_value());
      }
   }

GFpElement operator+(const GFpElement& lhs, const GFpElement& rhs)
   {
   // consider the case that lhs and rhs both use montgm:
   // then += returns an element which uses montgm.
   // thus the return value of op+ here will be an element
   // using montgm in this case
   // NOTE: the rhs might be transformed when using op+, the lhs never
   GFpElement result(lhs);
   result += rhs;
   return result;
   }

GFpElement operator-(const GFpElement& lhs, const GFpElement& rhs)
   {
   GFpElement result(lhs);
   result -= rhs;
   return result;
   // NOTE: the rhs might be transformed when using op-, the lhs never
   }

GFpElement operator-(const GFpElement& lhs)
   {
   return(GFpElement(lhs)).negate();
   }

GFpElement operator*(const GFpElement& lhs, const GFpElement& rhs)
   {
   // consider the case that lhs and rhs both use montgm:
   // then *= returns an element which uses montgm.
   // thus the return value of op* here will be an element
   // using montgm in this case
   GFpElement result(lhs);
   result *= rhs;
   return result;
   }

GFpElement operator*(const GFpElement& lhs, u32bit rhs)
   {
   GFpElement result(lhs);
   result *= rhs;
   return result;
   }

GFpElement operator*(u32bit lhs, const GFpElement& rhs)
   {
   return rhs*lhs;
   }

GFpElement operator/(const GFpElement& lhs, const GFpElement& rhs)
   {
   GFpElement result (lhs);
   result /= rhs;
   return result;
   }

SecureVector<byte> FE2OSP(const GFpElement& elem)
   {
   return BigInt::encode_1363(elem.get_value(), elem.get_p().bytes());
   }

GFpElement OS2FEP(MemoryRegion<byte> const& os, BigInt p)
   {
   return GFpElement(p, BigInt::decode(os.begin(), os.size()));
   }

GFpElement inverse(const GFpElement& elem)
   {
   return GFpElement(elem).inverse_in_place();
   }

}

