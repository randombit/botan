/*
* Arithmetic for prime fields GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*
* Distributed under the terms of the Botan license
*/

#include <botan/gfp_element.h>
#include <botan/numthry.h>
#include <botan/internal/def_powm.h>
#include <botan/internal/mp_asm.h>
#include <botan/internal/mp_asmi.h>
#include <ostream>
#include <assert.h>

namespace Botan {

namespace {

void inner_montg_mult_sos(word result[],
                          const word* a_bar, const word* b_bar,
                          const word* n, const word* n_dash, u32bit s)
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

         word tmp = t[i+s+cnt] + C;
         C = (tmp < t[i+s+cnt]);
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
* Calculates R=b^n (here b=2) with R>m (and R beeing as small as
* possible) for an odd modulus m. No check for parity is performed!
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
   : modulus(p), m_value(value %p), m_use_montgm(use_montgm), m_is_trf(false)
   {
   if(m_use_montgm)
      ensure_montgm_precomp();
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
   if((!modulus.get_r().is_zero()) && (!modulus.get_r_inv().is_zero()) && (!modulus.get_p_dash().is_zero()))
      {
      // values are already set, nothing more to do
      }
   else
      {
      BigInt tmp_r(montgm_calc_r_oddmod(modulus.get_p()));

      BigInt tmp_r_inv(inverse_mod(tmp_r, modulus.get_p()));

      BigInt tmp_p_dash(montgm_calc_m_dash(tmp_r, modulus.get_p(), tmp_r_inv));

      modulus.reset_values(tmp_p_dash, tmp_r, tmp_r_inv);
      }

   }

void GFpElement::trf_to_mres() const
   {
   if(!m_use_montgm)
      {
      throw Illegal_Transformation("GFpElement is not allowed to be transformed to m-residue");
      }
   assert(m_is_trf == false);
   assert(!modulus.get_r_inv().is_zero());
   assert(!modulus.get_p_dash().is_zero());
   m_value = montg_trf_to_mres(m_value, modulus.get_r(), modulus.get_p());
   m_is_trf = true;
   }

void GFpElement::trf_to_ordres() const
   {
   assert(m_is_trf == true);
   m_value = montg_trf_to_ordres(m_value, modulus.get_p(), modulus.get_r_inv());
   m_is_trf = false;
   }

bool GFpElement::align_operands_res(const GFpElement& lhs, const GFpElement& rhs) //static
   {
   assert(lhs.modulus.get_p() == rhs.modulus.get_p());
   if(lhs.m_use_montgm && rhs.m_use_montgm)
      {
      assert(rhs.modulus.get_p_dash() == lhs.modulus.get_p_dash());
      assert(rhs.modulus.get_r() == lhs.modulus.get_r());
      assert(rhs.modulus.get_r_inv() == lhs.modulus.get_r_inv());
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
   return (modulus.get_p());
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

GFpElement& GFpElement::operator+=(const GFpElement& rhs)
   {
   GFpElement::align_operands_res(*this, rhs);

   BigInt workspace = m_value;
   workspace += rhs.m_value;
   if(workspace >= modulus.get_p())
      workspace -= modulus.get_p();

   m_value = workspace;
   assert(m_value < modulus.get_p());
   assert(m_value >= 0);

   return *this;
   }

GFpElement& GFpElement::operator-=(const GFpElement& rhs)
   {
   GFpElement::align_operands_res(*this, rhs);

   BigInt workspace = m_value;

   workspace -= rhs.m_value;

   if(workspace.is_negative())
      workspace += modulus.get_p();

   m_value = workspace;
   assert(m_value < modulus.get_p());
   assert(m_value >= 0);
   return *this;
   }

GFpElement& GFpElement::operator*= (u32bit rhs)
   {
   BigInt workspace = m_value;
   workspace *= rhs;
   workspace %= modulus.get_p();
   m_value = workspace;
   return *this;
   }

GFpElement& GFpElement::operator*=(const GFpElement& rhs)
   {
   assert(rhs.modulus.get_p() == modulus.get_p());
   // here, we do not use align_operands_res() for one simple reason:
   // we want to enforce the transformation to an m-residue, otherwise it would
  // never happen
   if(m_use_montgm && rhs.m_use_montgm)
      {
      assert(rhs.modulus.get_p() == modulus.get_p()); // is montgm. mult is on, then precomps must be there
      assert(rhs.modulus.get_p_dash() == modulus.get_p_dash());
      assert(rhs.modulus.get_r() == modulus.get_r());
      if(!m_is_trf)
         {
         trf_to_mres();
         }
      if(!rhs.m_is_trf)
         {
         rhs.trf_to_mres();
         }
      BigInt workspace = m_value;
      montg_mult(m_value, workspace, rhs.m_value, modulus.get_p(), modulus.get_p_dash(), modulus.get_r());
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

      BigInt workspace = m_value;
      workspace *= rhs.m_value;
      workspace %= modulus.get_p();
      m_value = workspace;
      }
   return *this;
   }

GFpElement& GFpElement::operator/=(const GFpElement& rhs)
   {
   bool use_mres = GFpElement::align_operands_res(*this, rhs);
   assert((this->m_is_trf && rhs.m_is_trf) || !(this->m_is_trf && rhs.m_is_trf));

   if(use_mres)
      {
      assert(m_use_montgm && rhs.m_use_montgm);
      GFpElement rhs_ordres(rhs);
      rhs_ordres.trf_to_ordres();
      rhs_ordres.inverse_in_place();
      BigInt workspace = m_value;
      workspace *= rhs_ordres.get_value();
      workspace %= modulus.get_p();
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
   m_value = inverse_mod(m_value, modulus.get_p());

   if(m_is_trf)
      {
      assert(m_use_montgm);

      m_value *= modulus.get_r();
      m_value *= modulus.get_r();
      m_value %= modulus.get_p();
      }
   assert(m_value <= modulus.get_p());
   return *this;
   }

GFpElement& GFpElement::negate()
   {
   m_value = modulus.get_p() - m_value;
   assert(m_value <= modulus.get_p());
   return *this;
   }

void GFpElement::swap(GFpElement& other)
   {
   std::swap(m_value, other.m_value);
   std::swap(modulus, other.modulus);
   std::swap<bool>(m_use_montgm,other.m_use_montgm);
   std::swap<bool>(m_is_trf,other.m_is_trf);
   }

std::ostream& operator<<(std::ostream& output, const GFpElement& elem)
   {
   return output << '(' << elem.get_value() << "," << elem.get_p() << ')';
   }

bool operator==(const GFpElement& lhs, const GFpElement& rhs)
   {
   if(lhs.get_p() != rhs.get_p())
      return false;

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

