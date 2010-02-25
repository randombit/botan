/*
* Arithmetic for prime fields GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2008-2010 Jack Lloyd
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

GFpElement::GFpElement(const BigInt& p, const BigInt& value) :
   mod_p(p),
   m_value(value %p)
   {
   }

GFpElement& GFpElement::operator+=(const GFpElement& rhs)
   {
   BigInt workspace = m_value;
   workspace += rhs.m_value;
   if(workspace >= mod_p)
      workspace -= mod_p;

   m_value = workspace;
   assert(m_value < mod_p);
   assert(m_value >= 0);

   return *this;
   }

GFpElement& GFpElement::operator-=(const GFpElement& rhs)
   {
   BigInt workspace = m_value;

   workspace -= rhs.m_value;

   if(workspace.is_negative())
      workspace += mod_p;

   m_value = workspace;
   assert(m_value < mod_p);
   assert(m_value >= 0);
   return *this;
   }

GFpElement& GFpElement::operator*= (u32bit rhs)
   {
   BigInt workspace = m_value;
   workspace *= rhs;
   workspace %= mod_p;
   m_value = workspace;
   return *this;
   }

GFpElement& GFpElement::operator*=(const GFpElement& rhs)
   {
   BigInt workspace = m_value;
   workspace *= rhs.m_value;
   workspace %= mod_p;
   m_value = workspace;
   return *this;
   }

GFpElement& GFpElement::operator/=(const GFpElement& rhs)
   {
   GFpElement inv_rhs(rhs);
   inv_rhs.inverse_in_place();
   *this *= inv_rhs;
   return *this;
   }

bool GFpElement::is_zero() const
   {
   return (m_value.is_zero());
   // this is correct because x_bar = x * r = x = 0 for x = 0
   }

GFpElement& GFpElement::inverse_in_place()
   {
   m_value = inverse_mod(m_value, mod_p);
   return *this;
   }

GFpElement& GFpElement::negate()
   {
   m_value = mod_p - m_value;
   assert(m_value <= mod_p);
   return *this;
   }

void GFpElement::swap(GFpElement& other)
   {
   std::swap(m_value, other.m_value);
   std::swap(mod_p, other.mod_p);
   }

std::ostream& operator<<(std::ostream& output, const GFpElement& elem)
   {
   return output << '(' << elem.get_value() << "," << elem.get_p() << ')';
   }

bool operator==(const GFpElement& lhs, const GFpElement& rhs)
   {
   return (lhs.get_p() == rhs.get_p() &&
           lhs.get_value() == rhs.get_value());
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

