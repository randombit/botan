/*
* (C) 2015,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/point_mul.h>

#include <botan/reducer.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/rounding.h>

namespace Botan {

namespace {

size_t blinding_size(const BigInt& group_order) {
   return (group_order.bits() + 1) / 2;
}

}  // namespace

EC_Point multi_exponentiate(const EC_Point& x, const BigInt& z1, const EC_Point& y, const BigInt& z2) {
   EC_Point_Multi_Point_Precompute xy_mul(x, y);
   return xy_mul.multi_exp(z1, z2);
}

EC_Point_Base_Point_Precompute::EC_Point_Base_Point_Precompute(const EC_Point& base, const Modular_Reducer& mod_order) :
      m_base_point(base), m_mod_order(mod_order), m_p_words(base.get_curve().get_p_words()) {
   std::vector<BigInt> ws(EC_Point::WORKSPACE_SIZE);

   const size_t order_bits = mod_order.get_modulus().bits();

   const size_t T_bits = round_up(order_bits + blinding_size(mod_order.get_modulus()), WINDOW_BITS) / WINDOW_BITS;

   std::vector<EC_Point> T(WINDOW_SIZE * T_bits);

   EC_Point g = base;
   EC_Point g2, g4;

   for(size_t i = 0; i != T_bits; i++) {
      g2 = g;
      g2.mult2(ws);
      g4 = g2;
      g4.mult2(ws);

      T[7 * i + 0] = g;
      T[7 * i + 1] = std::move(g2);
      T[7 * i + 2] = T[7 * i + 1].plus(T[7 * i + 0], ws);  // g2+g
      T[7 * i + 3] = g4;
      T[7 * i + 4] = T[7 * i + 3].plus(T[7 * i + 0], ws);  // g4+g
      T[7 * i + 5] = T[7 * i + 3].plus(T[7 * i + 1], ws);  // g4+g2
      T[7 * i + 6] = T[7 * i + 3].plus(T[7 * i + 2], ws);  // g4+g2+g

      g.swap(g4);
      g.mult2(ws);
   }

   EC_Point::force_all_affine(T, ws[0].get_word_vector());

   m_W.resize(T.size() * 2 * m_p_words);

   word* p = &m_W[0];
   for(size_t i = 0; i != T.size(); ++i) {
      T[i].get_x().encode_words(p, m_p_words);
      p += m_p_words;
      T[i].get_y().encode_words(p, m_p_words);
      p += m_p_words;
   }
}

EC_Point EC_Point_Base_Point_Precompute::mul(const BigInt& k,
                                             RandomNumberGenerator& rng,
                                             const BigInt& group_order,
                                             std::vector<BigInt>& ws) const {
   if(k.is_negative()) {
      throw Invalid_Argument("EC_Point_Base_Point_Precompute scalar must be positive");
   }

   // Instead of reducing k mod group order should we alter the mask size??
   BigInt scalar = m_mod_order.reduce(k);

   if(rng.is_seeded()) {
      // Choose a small mask m and use k' = k + m*order (Coron's 1st countermeasure)
      const BigInt mask(rng, blinding_size(group_order));
      scalar += group_order * mask;
   } else {
      /*
      When we don't have an RNG we cannot do scalar blinding. Instead use the
      same trick as OpenSSL and add one or two copies of the order to normalize
      the length of the scalar at order.bits()+1. This at least ensures the loop
      bound does not leak information about the high bits of the scalar.
      */
      scalar += group_order;
      if(scalar.bits() == group_order.bits()) {
         scalar += group_order;
      }
      BOTAN_DEBUG_ASSERT(scalar.bits() == group_order.bits() + 1);
   }

   const size_t windows = round_up(scalar.bits(), WINDOW_BITS) / WINDOW_BITS;

   const size_t elem_size = 2 * m_p_words;

   BOTAN_ASSERT(windows <= m_W.size() / (3 * elem_size), "Precomputed sufficient values for scalar mult");

   EC_Point R = m_base_point.zero();

   if(ws.size() < EC_Point::WORKSPACE_SIZE) {
      ws.resize(EC_Point::WORKSPACE_SIZE);
   }

   // the precomputed multiples are not secret so use std::vector
   std::vector<word> Wt(elem_size);

   for(size_t i = 0; i != windows; ++i) {
      const size_t window = windows - i - 1;
      const size_t base_addr = (WINDOW_SIZE * window) * elem_size;

      const word w = scalar.get_substring(WINDOW_BITS * window, WINDOW_BITS);

      const auto w_is_1 = CT::Mask<word>::is_equal(w, 1);
      const auto w_is_2 = CT::Mask<word>::is_equal(w, 2);
      const auto w_is_3 = CT::Mask<word>::is_equal(w, 3);
      const auto w_is_4 = CT::Mask<word>::is_equal(w, 4);
      const auto w_is_5 = CT::Mask<word>::is_equal(w, 5);
      const auto w_is_6 = CT::Mask<word>::is_equal(w, 6);
      const auto w_is_7 = CT::Mask<word>::is_equal(w, 7);

      for(size_t j = 0; j != elem_size; ++j) {
         const word w1 = w_is_1.if_set_return(m_W[base_addr + 0 * elem_size + j]);
         const word w2 = w_is_2.if_set_return(m_W[base_addr + 1 * elem_size + j]);
         const word w3 = w_is_3.if_set_return(m_W[base_addr + 2 * elem_size + j]);
         const word w4 = w_is_4.if_set_return(m_W[base_addr + 3 * elem_size + j]);
         const word w5 = w_is_5.if_set_return(m_W[base_addr + 4 * elem_size + j]);
         const word w6 = w_is_6.if_set_return(m_W[base_addr + 5 * elem_size + j]);
         const word w7 = w_is_7.if_set_return(m_W[base_addr + 6 * elem_size + j]);

         Wt[j] = w1 | w2 | w3 | w4 | w5 | w6 | w7;
      }

      R.add_affine(&Wt[0], m_p_words, &Wt[m_p_words], m_p_words, ws);

      if(i == 0 && rng.is_seeded()) {
         /*
         * Since we start with the top bit of the exponent we know the
         * first window must have a non-zero element, and thus R is
         * now a point other than the point at infinity.
         */
         BOTAN_DEBUG_ASSERT(w != 0);
         R.randomize_repr(rng, ws[0].get_word_vector());
      }
   }

   BOTAN_DEBUG_ASSERT(R.on_the_curve());

   return R;
}

EC_Point_Var_Point_Precompute::EC_Point_Var_Point_Precompute(const EC_Point& point,
                                                             RandomNumberGenerator& rng,
                                                             std::vector<BigInt>& ws) :
      m_curve(point.get_curve()), m_p_words(m_curve.get_p_words()), m_window_bits(4) {
   if(ws.size() < EC_Point::WORKSPACE_SIZE) {
      ws.resize(EC_Point::WORKSPACE_SIZE);
   }

   std::vector<EC_Point> U(static_cast<size_t>(1) << m_window_bits);
   U[0] = point.zero();
   U[1] = point;

   for(size_t i = 2; i < U.size(); i += 2) {
      U[i] = U[i / 2].double_of(ws);
      U[i + 1] = U[i].plus(point, ws);
   }

   // Hack to handle Blinded_Point_Multiply
   if(rng.is_seeded()) {
      // Skipping zero point since it can't be randomized
      for(size_t i = 1; i != U.size(); ++i) {
         U[i].randomize_repr(rng);
      }
   }

   m_T.resize(U.size() * 3 * m_p_words);

   word* p = &m_T[0];
   for(size_t i = 0; i != U.size(); ++i) {
      U[i].get_x().encode_words(p, m_p_words);
      U[i].get_y().encode_words(p + m_p_words, m_p_words);
      U[i].get_z().encode_words(p + 2 * m_p_words, m_p_words);
      p += 3 * m_p_words;
   }
}

EC_Point EC_Point_Var_Point_Precompute::mul(const BigInt& k,
                                            RandomNumberGenerator& rng,
                                            const BigInt& group_order,
                                            std::vector<BigInt>& ws) const {
   if(k.is_negative()) {
      throw Invalid_Argument("EC_Point_Var_Point_Precompute scalar must be positive");
   }
   if(ws.size() < EC_Point::WORKSPACE_SIZE) {
      ws.resize(EC_Point::WORKSPACE_SIZE);
   }

   // Choose a small mask m and use k' = k + m*order (Coron's 1st countermeasure)
   const BigInt mask(rng, blinding_size(group_order), false);
   const BigInt scalar = k + group_order * mask;

   const size_t elem_size = 3 * m_p_words;
   const size_t window_elems = static_cast<size_t>(1) << m_window_bits;

   size_t windows = round_up(scalar.bits(), m_window_bits) / m_window_bits;
   EC_Point R(m_curve);
   secure_vector<word> e(elem_size);

   if(windows > 0) {
      windows--;

      const uint32_t w = scalar.get_substring(windows * m_window_bits, m_window_bits);

      clear_mem(e.data(), e.size());
      for(size_t i = 1; i != window_elems; ++i) {
         const auto wmask = CT::Mask<word>::is_equal(w, i);

         for(size_t j = 0; j != elem_size; ++j) {
            e[j] |= wmask.if_set_return(m_T[i * elem_size + j]);
         }
      }

      R.add(&e[0], m_p_words, &e[m_p_words], m_p_words, &e[2 * m_p_words], m_p_words, ws);

      /*
      Randomize after adding the first nibble as before the addition R
      is zero, and we cannot effectively randomize the point
      representation of the zero point.
      */
      R.randomize_repr(rng, ws[0].get_word_vector());
   }

   while(windows) {
      R.mult2i(m_window_bits, ws);

      const uint32_t w = scalar.get_substring((windows - 1) * m_window_bits, m_window_bits);

      clear_mem(e.data(), e.size());
      for(size_t i = 1; i != window_elems; ++i) {
         const auto wmask = CT::Mask<word>::is_equal(w, i);

         for(size_t j = 0; j != elem_size; ++j) {
            e[j] |= wmask.if_set_return(m_T[i * elem_size + j]);
         }
      }

      R.add(&e[0], m_p_words, &e[m_p_words], m_p_words, &e[2 * m_p_words], m_p_words, ws);

      windows--;
   }

   BOTAN_DEBUG_ASSERT(R.on_the_curve());

   return R;
}

EC_Point_Multi_Point_Precompute::EC_Point_Multi_Point_Precompute(const EC_Point& x, const EC_Point& y) {
   if(x.on_the_curve() == false || y.on_the_curve() == false) {
      m_M.push_back(x.zero());
      return;
   }

   std::vector<BigInt> ws(EC_Point::WORKSPACE_SIZE);

   EC_Point x2 = x;
   x2.mult2(ws);

   const EC_Point x3(x2.plus(x, ws));

   EC_Point y2 = y;
   y2.mult2(ws);

   const EC_Point y3(y2.plus(y, ws));

   m_M.reserve(15);

   m_M.push_back(x);
   m_M.push_back(x2);
   m_M.push_back(x3);

   m_M.push_back(y);
   m_M.push_back(y.plus(x, ws));
   m_M.push_back(y.plus(x2, ws));
   m_M.push_back(y.plus(x3, ws));

   m_M.push_back(y2);
   m_M.push_back(y2.plus(x, ws));
   m_M.push_back(y2.plus(x2, ws));
   m_M.push_back(y2.plus(x3, ws));

   m_M.push_back(y3);
   m_M.push_back(y3.plus(x, ws));
   m_M.push_back(y3.plus(x2, ws));
   m_M.push_back(y3.plus(x3, ws));

   bool no_infinity = true;
   for(auto& pt : m_M) {
      if(pt.is_zero()) {
         no_infinity = false;
      }
   }

   if(no_infinity) {
      EC_Point::force_all_affine(m_M, ws[0].get_word_vector());
   }

   m_no_infinity = no_infinity;
}

EC_Point EC_Point_Multi_Point_Precompute::multi_exp(const BigInt& z1, const BigInt& z2) const {
   if(m_M.size() == 1) {
      return m_M[0];
   }

   std::vector<BigInt> ws(EC_Point::WORKSPACE_SIZE);

   const size_t z_bits = round_up(std::max(z1.bits(), z2.bits()), 2);

   EC_Point H = m_M[0].zero();

   for(size_t i = 0; i != z_bits; i += 2) {
      if(i > 0) {
         H.mult2i(2, ws);
      }

      const uint32_t z1_b = z1.get_substring(z_bits - i - 2, 2);
      const uint32_t z2_b = z2.get_substring(z_bits - i - 2, 2);

      const uint32_t z12 = (4 * z2_b) + z1_b;

      // This function is not intended to be const time
      if(z12) {
         if(m_no_infinity) {
            H.add_affine(m_M[z12 - 1], ws);
         } else {
            H.add(m_M[z12 - 1], ws);
         }
      }
   }

   if(z1.is_negative() != z2.is_negative()) {
      H.negate();
   }

   return H;
}

}  // namespace Botan
