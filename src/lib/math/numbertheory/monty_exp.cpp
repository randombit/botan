/*
* Montgomery Exponentiation
* (C) 1999-2010,2012,2018,2025 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/monty_exp.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/monty.h>
#include <botan/internal/rounding.h>

namespace Botan {

class Montgomery_Exponentation_State final {
   public:
      Montgomery_Exponentation_State(const Montgomery_Int& g, size_t window_bits, bool const_time);

      Montgomery_Int exponentiation(const BigInt& k, size_t max_k_bits) const;

      Montgomery_Int exponentiation_vartime(const BigInt& k) const;

   private:
      std::shared_ptr<const Montgomery_Params> m_params;
      std::vector<Montgomery_Int> m_g;
      size_t m_window_bits;
};

Montgomery_Exponentation_State::Montgomery_Exponentation_State(const Montgomery_Int& g,
                                                               size_t window_bits,
                                                               bool const_time) :
      m_params(g._params()), m_window_bits(window_bits == 0 ? 4 : window_bits) {
   if(m_window_bits < 1 || m_window_bits > 12) {  // really even 8 is too large ...
      throw Invalid_Argument("Invalid window bits for Montgomery exponentiation");
   }

   const size_t window_size = (static_cast<size_t>(1) << m_window_bits);

   m_g.reserve(window_size);

   m_g.push_back(Montgomery_Int::one(m_params));

   m_g.push_back(g);

   for(size_t i = 2; i != window_size; ++i) {
      m_g.push_back(m_g[1] * m_g[i - 1]);
   }

   // Resize each element to exactly p words
   for(auto& x : m_g) {
      x.fix_size();
   }

   if(const_time) {
      CT::poison_range(m_g);
   }
}

namespace {

void const_time_lookup(secure_vector<word>& output, const std::vector<Montgomery_Int>& g, size_t nibble) {
   BOTAN_ASSERT_NOMSG(g.size() % 2 == 0);  // actually a power of 2

   const size_t words = output.size();

   clear_mem(output.data(), output.size());

   for(size_t i = 0; i != g.size(); i += 2) {
      const secure_vector<word>& vec_0 = g[i].repr().get_word_vector();
      const secure_vector<word>& vec_1 = g[i + 1].repr().get_word_vector();

      BOTAN_ASSERT_NOMSG(vec_0.size() >= words && vec_1.size() >= words);

      const auto mask_0 = CT::Mask<word>::is_equal(nibble, i);
      const auto mask_1 = CT::Mask<word>::is_equal(nibble, i + 1);

      for(size_t w = 0; w != words; ++w) {
         output[w] |= mask_0.if_set_return(vec_0[w]);
         output[w] |= mask_1.if_set_return(vec_1[w]);
      }
   }
}

}  // namespace

Montgomery_Int Montgomery_Exponentation_State::exponentiation(const BigInt& scalar, size_t max_k_bits) const {
   BOTAN_DEBUG_ASSERT(scalar.bits() <= max_k_bits);
   // TODO add a const-time implementation of above assert and use it in release builds

   const size_t exp_nibbles = (max_k_bits + m_window_bits - 1) / m_window_bits;

   if(exp_nibbles == 0) {
      return Montgomery_Int::one(m_params);
   }

   secure_vector<word> e_bits(m_params->p_words());
   secure_vector<word> ws;

   const_time_lookup(e_bits, m_g, scalar.get_substring(m_window_bits * (exp_nibbles - 1), m_window_bits));
   Montgomery_Int x(m_params, e_bits.data(), e_bits.size(), false);

   for(size_t i = exp_nibbles - 1; i > 0; --i) {
      x.square_this_n_times(ws, m_window_bits);
      const_time_lookup(e_bits, m_g, scalar.get_substring(m_window_bits * (i - 1), m_window_bits));
      x.mul_by(e_bits, ws);
   }

   CT::unpoison(x);
   return x;
}

Montgomery_Int Montgomery_Exponentation_State::exponentiation_vartime(const BigInt& scalar) const {
   const size_t exp_nibbles = (scalar.bits() + m_window_bits - 1) / m_window_bits;

   secure_vector<word> ws;

   if(exp_nibbles == 0) {
      return Montgomery_Int::one(m_params);
   }

   Montgomery_Int x = m_g[scalar.get_substring(m_window_bits * (exp_nibbles - 1), m_window_bits)];

   for(size_t i = exp_nibbles - 1; i > 0; --i) {
      x.square_this_n_times(ws, m_window_bits);

      const uint32_t nibble = scalar.get_substring(m_window_bits * (i - 1), m_window_bits);
      if(nibble > 0) {
         x.mul_by(m_g[nibble], ws);
      }
   }

   CT::unpoison(x);
   return x;
}

std::shared_ptr<const Montgomery_Exponentation_State> monty_precompute(const Montgomery_Int& g,
                                                                       size_t window_bits,
                                                                       bool const_time) {
   return std::make_shared<const Montgomery_Exponentation_State>(g, window_bits, const_time);
}

std::shared_ptr<const Montgomery_Exponentation_State> monty_precompute(
   const std::shared_ptr<const Montgomery_Params>& params, const BigInt& g, size_t window_bits, bool const_time) {
   BOTAN_ARG_CHECK(g < params->p(), "Montgomery base too big");
   Montgomery_Int monty_g(params, g);
   return monty_precompute(monty_g, window_bits, const_time);
}

Montgomery_Int monty_execute(const Montgomery_Exponentation_State& precomputed_state,
                             const BigInt& k,
                             size_t max_k_bits) {
   return precomputed_state.exponentiation(k, max_k_bits);
}

Montgomery_Int monty_execute_vartime(const Montgomery_Exponentation_State& precomputed_state, const BigInt& k) {
   return precomputed_state.exponentiation_vartime(k);
}

Montgomery_Int monty_multi_exp(const std::shared_ptr<const Montgomery_Params>& params_p,
                               const BigInt& x_bn,
                               const BigInt& z1,
                               const BigInt& y_bn,
                               const BigInt& z2) {
   if(z1.is_negative() || z2.is_negative()) {
      throw Invalid_Argument("multi_exponentiate exponents must be positive");
   }

   const size_t z_bits = round_up(std::max(z1.bits(), z2.bits()), 2);

   secure_vector<word> ws;

   const Montgomery_Int one(params_p, params_p->R1(), false);
   //const Montgomery_Int one(params_p, 1);

   const Montgomery_Int x1(params_p, x_bn);
   const Montgomery_Int x2 = x1.square(ws);
   const Montgomery_Int x3 = x2.mul(x1, ws);

   const Montgomery_Int y1(params_p, y_bn);
   const Montgomery_Int y2 = y1.square(ws);
   const Montgomery_Int y3 = y2.mul(y1, ws);

   const Montgomery_Int y1x1 = y1.mul(x1, ws);
   const Montgomery_Int y1x2 = y1.mul(x2, ws);
   const Montgomery_Int y1x3 = y1.mul(x3, ws);

   const Montgomery_Int y2x1 = y2.mul(x1, ws);
   const Montgomery_Int y2x2 = y2.mul(x2, ws);
   const Montgomery_Int y2x3 = y2.mul(x3, ws);

   const Montgomery_Int y3x1 = y3.mul(x1, ws);
   const Montgomery_Int y3x2 = y3.mul(x2, ws);
   const Montgomery_Int y3x3 = y3.mul(x3, ws);

   const Montgomery_Int* M[16] = {&one,
                                  &x1,  // 0001
                                  &x2,  // 0010
                                  &x3,  // 0011
                                  &y1,  // 0100
                                  &y1x1,
                                  &y1x2,
                                  &y1x3,
                                  &y2,  // 1000
                                  &y2x1,
                                  &y2x2,
                                  &y2x3,
                                  &y3,  // 1100
                                  &y3x1,
                                  &y3x2,
                                  &y3x3};

   Montgomery_Int H = one;

   for(size_t i = 0; i != z_bits; i += 2) {
      if(i > 0) {
         H.square_this(ws);
         H.square_this(ws);
      }

      const uint32_t z1_b = z1.get_substring(z_bits - i - 2, 2);
      const uint32_t z2_b = z2.get_substring(z_bits - i - 2, 2);

      const uint32_t z12 = (4 * z2_b) + z1_b;

      H.mul_by(*M[z12], ws);
   }

   return H;
}

}  // namespace Botan
