/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_POINT_MUL_H_
#define BOTAN_POINT_MUL_H_

#include <botan/ec_point.h>

namespace Botan {

class Modular_Reducer;

class EC_Point_Base_Point_Precompute final {
   public:
      EC_Point_Base_Point_Precompute(const EC_Point& base_point, const Modular_Reducer& mod_order);

      EC_Point mul(const BigInt& k,
                   RandomNumberGenerator& rng,
                   const BigInt& group_order,
                   std::vector<BigInt>& ws) const;

   private:
      const EC_Point& m_base_point;
      const Modular_Reducer& m_mod_order;

      enum { WINDOW_BITS = 3 };

      enum { WINDOW_SIZE = (1 << WINDOW_BITS) - 1 };

      const size_t m_p_words;

      /*
      * This is a table of T_size * 3*p_word words
      */
      std::vector<word> m_W;
};

class EC_Point_Var_Point_Precompute final {
   public:
      EC_Point_Var_Point_Precompute(const EC_Point& point, RandomNumberGenerator& rng, std::vector<BigInt>& ws);

      EC_Point mul(const BigInt& k,
                   RandomNumberGenerator& rng,
                   const BigInt& group_order,
                   std::vector<BigInt>& ws) const;

   private:
      const CurveGFp m_curve;
      const size_t m_p_words;
      const size_t m_window_bits;

      /*
      * Table of 2^window_bits * 3*2*p_word words
      * Kept in locked vector since the base point might be sensitive
      * (normally isn't in most protocols but hard to say anything
      * categorically.)
      */
      secure_vector<word> m_T;
};

class EC_Point_Multi_Point_Precompute final {
   public:
      EC_Point_Multi_Point_Precompute(const EC_Point& g1, const EC_Point& g2);

      /*
      * Return (g1*k1 + g2*k2)
      * Not constant time, intended to use with public inputs
      */
      EC_Point multi_exp(const BigInt& k1, const BigInt& k2) const;

   private:
      std::vector<EC_Point> m_M;
      bool m_no_infinity;
};

}  // namespace Botan

#endif
