/******************************************************
 * Elliptic curves over GF(p) (source file)           *
 *                                                    *
 * (C) 2007 Martin Döring                             *
 *          doering@cdc.informatik.tu-darmstadt.de    *
 *          Christoph Ludwig                          *
 *          ludwig@fh-worms.de                        *
 *          Falko Strenzke                            *
 *          strenzke@flexsecure.de                    *
 ******************************************************/

#include <botan/curve_gfp.h>
#include <botan/bigint.h>

namespace Botan {

void CurveGFp::set_shrd_mod(SharedPtrConverter<GFpModulus> const mod)
   {
   mp_mod = mod.get_shared();
   mA.turn_off_sp_red_mul();// m.m. is not needed, must be trf. back
   mB.turn_off_sp_red_mul();// m.m. is not needed, must be trf. back
   //ok, above we destroy any evantually computated montg. mult. values,
   // but that won´t influence performance in usual applications
   mA.set_shrd_mod(mod.get_shared());
   mB.set_shrd_mod(mod.get_shared());
   }

CurveGFp::CurveGFp(gf::GFpElement const& a, gf::GFpElement const& b,
                   BigInt const& p)
   : 	mA(a),
        mB(b)
   {
   if(!((p == mA.get_p()) && (p == mB.get_p())))
      {
      throw Invalid_Argument("could not construct curve: moduli of arguments differ");
      }
   std::tr1::shared_ptr<GFpModulus> p_mod = std::tr1::shared_ptr<GFpModulus>(new GFpModulus(p));
   // the above is the creation of the GFpModuls object which will be shared point-wide
   // (in the context of a point of course)
   set_shrd_mod(p_mod);
   }

// copy constructor
CurveGFp::CurveGFp(CurveGFp const& other)
   :	mA(other.get_a()),
        mB(other.get_b())
   {
   mp_mod = std::tr1::shared_ptr<GFpModulus>(new GFpModulus(*other.mp_mod));
   assert(mp_mod->p_equal_to(mA.get_p()));
   assert(mp_mod->p_equal_to(mB.get_p()));
   set_shrd_mod(mp_mod);
   if(other.mp_mres_a.get())
      {
      mp_mres_a = std::tr1::shared_ptr<GFpElement>(new GFpElement(*other.mp_mres_a));
      }
   if(other.mp_mres_b.get())
      {
      mp_mres_b = std::tr1::shared_ptr<GFpElement>(new GFpElement(*other.mp_mres_b));
      }
   if(other.mp_mres_one.get())
      {
      mp_mres_one = std::tr1::shared_ptr<GFpElement>(new GFpElement(*other.mp_mres_one));
      }

   }

// assignment operator
CurveGFp const& CurveGFp::operator=(CurveGFp const& other)
   {
   // for exception safety...
   GFpElement a_tmp = other.mA;
   GFpElement b_tmp = other.mB;
   mA.swap(a_tmp);
   mB.swap(b_tmp);

   std::tr1::shared_ptr<GFpModulus> p_mod = std::tr1::shared_ptr<GFpModulus>(new GFpModulus(*other.mp_mod));
   set_shrd_mod(p_mod);

   // exception safety note: no problem if we have a throw from here on...
   if(other.mp_mres_a.get())
      {
      mp_mres_a = std::tr1::shared_ptr<GFpElement>(new GFpElement(*other.mp_mres_a));
      }
   if(other.mp_mres_b.get())
      {
      mp_mres_b = std::tr1::shared_ptr<GFpElement>(new GFpElement(*other.mp_mres_b));
      }
   if(other.mp_mres_one.get())
      {
      mp_mres_one = std::tr1::shared_ptr<GFpElement>(new GFpElement(*other.mp_mres_one));
      }
   return *this;
   }

// getters
gf::GFpElement const CurveGFp::get_a() const
   {
   return mA;
   }
gf::GFpElement const CurveGFp::get_b() const
   {
   return mB;
   }

BigInt const CurveGFp::get_p() const
   {
   assert(mp_mod.get() != 0);
   return mp_mod->get_p();
   }

// swaps the states of *this and other, does not throw
void CurveGFp::swap(CurveGFp& other)
   {
   mA.swap(other.mA);
   mB.swap(other.mB);
   mp_mod.swap(other.mp_mod);
   std::swap(mp_mres_a, other.mp_mres_a);
   std::swap(mp_mres_b, other.mp_mres_b);
   std::swap(mp_mres_one, other.mp_mres_one);
   }

gf::GFpElement const CurveGFp::get_mres_a() const
   {
   if(mp_mres_a.get() == 0)
      {
      mp_mres_a = std::tr1::shared_ptr<GFpElement>(new GFpElement(mA));
      mp_mres_a->turn_on_sp_red_mul();
      mp_mres_a->get_mres();
      }
   return GFpElement(*mp_mres_a);
   }

gf::GFpElement const CurveGFp::get_mres_b() const
   {
   if(mp_mres_b.get() == 0)
      {
      mp_mres_b = std::tr1::shared_ptr<GFpElement>(new GFpElement(mB));
      mp_mres_b->turn_on_sp_red_mul();
      mp_mres_b->get_mres();
      }
   return GFpElement(*mp_mres_b);
   }

std::tr1::shared_ptr<gf::GFpElement const> const CurveGFp::get_mres_one() const
   {
   if(mp_mres_one.get() == 0)
      {
      mp_mres_one = std::tr1::shared_ptr<GFpElement>(new GFpElement(mp_mod->get_p(), 1));
      mp_mres_one->turn_on_sp_red_mul();
      mp_mres_one->get_mres();
      }
   return mp_mres_one;
   }

bool operator==(CurveGFp const& lhs, CurveGFp const& rhs)
   {
   return (lhs.get_p() == rhs.get_p() && lhs.get_a() == rhs.get_a() && lhs.get_b() == rhs.get_b());
   }

std::ostream& operator<<(std::ostream& output, const CurveGFp& elem)
   {
   return output << "y^2 = x^3 + (" << elem.get_a() << ")x + (" << elem.get_b() << ")";
   }

}
