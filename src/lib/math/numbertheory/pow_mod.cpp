/*
* Modular Exponentiation Proxy
* (C) 1999-2007,2012,2018,2019 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pow_mod.h>
#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/monty.h>
#include <botan/internal/monty_exp.h>
#include <botan/internal/rounding.h>
#include <vector>

namespace Botan {

class Modular_Exponentiator
   {
   public:
      virtual void set_base(const BigInt&) = 0;
      virtual void set_exponent(const BigInt&) = 0;
      virtual BigInt execute() const = 0;
      virtual Modular_Exponentiator* copy() const = 0;

      Modular_Exponentiator() = default;
      Modular_Exponentiator(const Modular_Exponentiator&) = default;
      Modular_Exponentiator & operator=(const Modular_Exponentiator&) = default;
      virtual ~Modular_Exponentiator() = default;
   };

namespace {

/**
* Fixed Window Exponentiator
*/
class Fixed_Window_Exponentiator final : public Modular_Exponentiator
   {
   public:
      void set_exponent(const BigInt& e) override { m_exp = e; }
      void set_base(const BigInt&) override;
      BigInt execute() const override;

      Modular_Exponentiator* copy() const override
         { return new Fixed_Window_Exponentiator(*this); }

      Fixed_Window_Exponentiator(const BigInt&, Power_Mod::Usage_Hints);
   private:
      Modular_Reducer m_reducer;
      BigInt m_exp;
      size_t m_window_bits;
      std::vector<BigInt> m_g;
      Power_Mod::Usage_Hints m_hints;
   };

void Fixed_Window_Exponentiator::set_base(const BigInt& base)
   {
   m_window_bits = Power_Mod::window_bits(m_exp.bits(), base.bits(), m_hints);

   m_g.resize(static_cast<size_t>(1) << m_window_bits);
   m_g[0] = 1;
   m_g[1] = m_reducer.reduce(base);

   for(size_t i = 2; i != m_g.size(); ++i)
      m_g[i] = m_reducer.multiply(m_g[i-1], m_g[1]);
   }

BigInt Fixed_Window_Exponentiator::execute() const
   {
   const size_t exp_nibbles = (m_exp.bits() + m_window_bits - 1) / m_window_bits;

   BigInt x = 1;

   for(size_t i = exp_nibbles; i > 0; --i)
      {
      for(size_t j = 0; j != m_window_bits; ++j)
         x = m_reducer.square(x);

      const uint32_t nibble = m_exp.get_substring(m_window_bits*(i-1), m_window_bits);

      // not const time:
      x = m_reducer.multiply(x, m_g[nibble]);
      }
   return x;
   }

/*
* Fixed_Window_Exponentiator Constructor
*/
Fixed_Window_Exponentiator::Fixed_Window_Exponentiator(const BigInt& n,
                                                       Power_Mod::Usage_Hints hints)
   : m_reducer{Modular_Reducer(n)}, m_exp{}, m_window_bits{}, m_g{}, m_hints{hints}
   {}

class Montgomery_Exponentiator final : public Modular_Exponentiator
   {
   public:
      void set_exponent(const BigInt& e) override { m_e = e; }
      void set_base(const BigInt&) override;
      BigInt execute() const override;

      Modular_Exponentiator* copy() const override
         { return new Montgomery_Exponentiator(*this); }

      Montgomery_Exponentiator(const BigInt&, Power_Mod::Usage_Hints);
   private:
      BigInt m_p;
      Modular_Reducer m_mod_p;
      std::shared_ptr<const Montgomery_Params> m_monty_params;
      std::shared_ptr<const Montgomery_Exponentation_State> m_monty;

      BigInt m_e;
      Power_Mod::Usage_Hints m_hints;
   };

void Montgomery_Exponentiator::set_base(const BigInt& base)
   {
   size_t window_bits = Power_Mod::window_bits(m_e.bits(), base.bits(), m_hints);
   m_monty = monty_precompute(m_monty_params, m_mod_p.reduce(base), window_bits);
   }

BigInt Montgomery_Exponentiator::execute() const
   {
   /*
   This leaks size of e via loop iterations, not possible to fix without
   breaking this API. Round up to avoid leaking fine details.
   */
   return monty_execute(*m_monty, m_e, round_up(m_e.bits(), 8));
   }

Montgomery_Exponentiator::Montgomery_Exponentiator(const BigInt& mod,
                                                   Power_Mod::Usage_Hints hints) :
   m_p(mod),
   m_mod_p(mod),
   m_monty_params(std::make_shared<Montgomery_Params>(m_p, m_mod_p)),
   m_hints(hints)
   {
   }

}

/*
* Power_Mod Constructor
*/
Power_Mod::Power_Mod(const BigInt& n, Usage_Hints hints, bool disable_monty)
   {
   set_modulus(n, hints, disable_monty);
   }

Power_Mod::~Power_Mod() { /* for ~unique_ptr */ }

/*
* Power_Mod Copy Constructor
*/
Power_Mod::Power_Mod(const Power_Mod& other)
   {
   if(other.m_core.get())
      m_core.reset(other.m_core->copy());
   }

/*
* Power_Mod Assignment Operator
*/
Power_Mod& Power_Mod::operator=(const Power_Mod& other)
   {
   if(this != &other)
      {
      if(other.m_core)
         m_core.reset(other.m_core->copy());
      else
         m_core.reset();
      }
   return (*this);
   }

/*
* Set the modulus
*/
void Power_Mod::set_modulus(const BigInt& n, Usage_Hints hints, bool disable_monty) const
   {
   // Allow set_modulus(0) to mean "drop old state"

   m_core.reset();

   if(n != 0)
      {
      if(n.is_odd() && disable_monty == false)
         m_core.reset(new Montgomery_Exponentiator(n, hints));
      else
         m_core.reset(new Fixed_Window_Exponentiator(n, hints));
      }
   }

/*
* Set the base
*/
void Power_Mod::set_base(const BigInt& b) const
   {
   if(b.is_negative())
      throw Invalid_Argument("Power_Mod::set_base: arg must be non-negative");

   if(!m_core)
      throw Internal_Error("Power_Mod::set_base: m_core was NULL");
   m_core->set_base(b);
   }

/*
* Set the exponent
*/
void Power_Mod::set_exponent(const BigInt& e) const
   {
   if(e.is_negative())
      throw Invalid_Argument("Power_Mod::set_exponent: arg must be > 0");

   if(!m_core)
      throw Internal_Error("Power_Mod::set_exponent: m_core was NULL");
   m_core->set_exponent(e);
   }

/*
* Compute the result
*/
BigInt Power_Mod::execute() const
   {
   if(!m_core)
      throw Internal_Error("Power_Mod::execute: m_core was NULL");
   return m_core->execute();
   }

/*
* Try to choose a good window size
*/
size_t Power_Mod::window_bits(size_t exp_bits, size_t,
                              Power_Mod::Usage_Hints hints)
   {
   static const size_t wsize[][2] = {
      { 1434, 7 },
      {  539, 6 },
      {  197, 4 },
      {   70, 3 },
      {   17, 2 },
      {    0, 0 }
   };

   size_t window_bits = 1;

   if(exp_bits)
      {
      for(size_t j = 0; wsize[j][0]; ++j)
         {
         if(exp_bits >= wsize[j][0])
            {
            window_bits += wsize[j][1];
            break;
            }
         }
      }

   if(hints & Power_Mod::BASE_IS_FIXED)
      window_bits += 2;
   if(hints & Power_Mod::EXP_IS_LARGE)
      ++window_bits;

   return window_bits;
   }

namespace {

/*
* Choose potentially useful hints
*/
Power_Mod::Usage_Hints choose_base_hints(const BigInt& b, const BigInt& n)
   {
   if(b == 2)
      return Power_Mod::Usage_Hints(Power_Mod::BASE_IS_2 |
                                    Power_Mod::BASE_IS_SMALL);

   const size_t b_bits = b.bits();
   const size_t n_bits = n.bits();

   if(b_bits < n_bits / 32)
      return Power_Mod::BASE_IS_SMALL;
   if(b_bits > n_bits / 4)
      return Power_Mod::BASE_IS_LARGE;

   return Power_Mod::NO_HINTS;
   }

/*
* Choose potentially useful hints
*/
Power_Mod::Usage_Hints choose_exp_hints(const BigInt& e, const BigInt& n)
   {
   const size_t e_bits = e.bits();
   const size_t n_bits = n.bits();

   if(e_bits < n_bits / 32)
      return Power_Mod::BASE_IS_SMALL;
   if(e_bits > n_bits / 4)
      return Power_Mod::BASE_IS_LARGE;
   return Power_Mod::NO_HINTS;
   }

}

/*
* Fixed_Exponent_Power_Mod Constructor
*/
Fixed_Exponent_Power_Mod::Fixed_Exponent_Power_Mod(const BigInt& e,
                                                   const BigInt& n,
                                                   Usage_Hints hints) :
   Power_Mod(n, Usage_Hints(hints | EXP_IS_FIXED | choose_exp_hints(e, n)))
   {
   set_exponent(e);
   }

/*
* Fixed_Base_Power_Mod Constructor
*/
Fixed_Base_Power_Mod::Fixed_Base_Power_Mod(const BigInt& b, const BigInt& n,
                                           Usage_Hints hints) :
   Power_Mod(n, Usage_Hints(hints | BASE_IS_FIXED | choose_base_hints(b, n)))
   {
   set_base(b);
   }

}
