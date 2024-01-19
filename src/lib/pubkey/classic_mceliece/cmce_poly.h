/*
 * Classic McEliece Polynomials
 * (C) 2023 Jack Lloyd
 *     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_CMCE_POLY_H_
#define BOTAN_CMCE_POLY_H_

#include <botan/secmem.h>
#include <botan/internal/cmce_gf.h>
#include <botan/internal/loadstor.h>

#include <optional>

namespace Botan {

/**
 * @brief Representation of a Classic McEliece polynomial.
 *
 * This class represents a polynomial in the ring GF(q)[y]. E.g an example element of degree 2 could be:
 * a = (z^3+1)y^2 + (z)y + (z^4+z^3)
 * The degree of the polynomial is given by the size of the coefficient vector given to
 * the constructor, even if the leading coefficient is zero. Coefficients are stored from
 * lowest to highest monomial degree (coef_at(0) = (z^4+z^3) in the example above).
 *
 * This class is merely a container. The modulus and the operations with Polynomials (e.g. multiplication)
 * is handled by the Classic_McEliece_Polynomial_Ring class.
 */
class BOTAN_TEST_API Classic_McEliece_Polynomial {
   public:
      /**
       * @brief Construct a polynomial given its coefficients.
       *
       * @param coef The coefficients of the polynomial. The first element is the coefficient of the lowest monomial.
       */
      Classic_McEliece_Polynomial(std::vector<Classic_McEliece_GF> coef) : m_coef(std::move(coef)) {}

      /**
       * @brief Evaluate the polynomial P(x) at a given point a, i.e., compute P(a).
       */
      Classic_McEliece_GF operator()(Classic_McEliece_GF a) const;

      /**
       * @brief Get the coefficient of the i-th monomial as a reference (from low to high degree).
       */
      Classic_McEliece_GF& coef_at(size_t i) { return m_coef.at(i); }

      /**
       * @brief Get the coefficient of the i-th monomial (from low to high degree).
       */
      const Classic_McEliece_GF& coef_at(size_t i) const { return m_coef.at(i); }

      /**
       * @brief Get the entire coefficients vector of the polynomial.
       */
      const std::vector<Classic_McEliece_GF>& coef() const { return m_coef; }

      /**
       * @brief Get the degree of the polynomial.
       *
       * Note that the degree is given by the size of the coefficient vector, even if the leading coefficient is zero.
       */
      size_t degree() const { return m_coef.size() + 1; }

      void _const_time_poison() const { CT::poison(m_coef); }

      void _const_time_unpoison() const { CT::unpoison(m_coef); }

   private:
      std::vector<Classic_McEliece_GF> m_coef;
};

/**
 * @brief Representation of a minimal polynomial in GF(q)[y].
 *
 * It represents the monic irreducible degree-t polynomial of the goppa code.
 */
class BOTAN_TEST_API Classic_McEliece_Minimal_Polynomial : public Classic_McEliece_Polynomial {
   public:
      Classic_McEliece_Minimal_Polynomial(std::vector<Classic_McEliece_GF> coef) :
            Classic_McEliece_Polynomial(std::move(coef)) {}

      /**
       * @brief Serialize the polynomial to bytes according to ISO Section 9.2.9.
       */
      secure_vector<uint8_t> serialize() const;

      /**
       * @brief Create a polynomial from bytes according to ISO Section 9.2.9.
       */
      static Classic_McEliece_Minimal_Polynomial from_bytes(std::span<const uint8_t> bytes, CmceGfMod poly_f);
};

/**
 * @brief Represents the polynomial ring GF(q)[y]/F(y) where F(y) is the modulus polynomial in
 * GF(q)[y] of degree t.
 *
 * This class contains a modulus polynomial F(y) and the GF(q) modulus f(z). It is used
 * to create and operate with Classic_McEliece_Polynomials.
 */
class BOTAN_TEST_API Classic_McEliece_Polynomial_Ring {
   public:
      /**
       * @brief Represents a non-zero coefficient of the modulus F(y) (which is in GF(q)[y]).
       *
       * E.g. {.idx = 4, .coeff = (z+1)} represents the monomial (z+1)y^4.
       */
      struct BOTAN_TEST_API Big_F_Coefficient {
            size_t idx;
            Classic_McEliece_GF coeff;
      };

      /**
       * @brief Construct a polynomial ring GF(q)[y]/F(y) by defining the polynomial modulus F(y),
       * the GF(q) modulus f(z) and the degree of F(y).
       *
       * F(y) is given by a vector of Big_F_Coefficients, where each one represents a monomial of F(y).
       * However, the highest monomial must not be specified, since it is always 1.
       *
       * @param poly_big_f_coef The non-zero coefficients of F(y) in GF(q)[y] WITHOUT the highest monomial.
       * @param poly_f The modulus f(z) of GF(q).
       * @param t The polynomial degree of the ring (and of F(y)).
       */
      Classic_McEliece_Polynomial_Ring(std::vector<Big_F_Coefficient> poly_big_f_coef, CmceGfMod poly_f, size_t t) :
            m_position_map(std::move(poly_big_f_coef)), m_t(t), m_poly_f(poly_f) {}

      CmceGfMod poly_f() const { return m_poly_f; }

      /**
       * @brief The degree of polynomials in this ring (and of F(y)).
       */
      size_t degree() const { return m_t; }

      /**
       * @returns a*b over GF(q)[y]/F(y).
       */
      Classic_McEliece_Polynomial multiply(const Classic_McEliece_Polynomial& a,
                                           const Classic_McEliece_Polynomial& b) const;

      /**
       * @brief Compute the minimal polynomial g of polynomial created from a @p seed.
       *
       * @param seed over the ring GF(q)[y] according to ISO Section 8.1 Step 3.
       *
       * @return g or std::nullopt if g has not full degree.
       */
      std::optional<Classic_McEliece_Minimal_Polynomial> compute_minimal_polynomial(
         StrongSpan<const CmceIrreducibleBits> seed) const;

   private:
      // Creates a ring element from a coefficient vector
      Classic_McEliece_Polynomial create_element_from_coef(const std::vector<CmceGfElem>& coeff_vec) const;

      /**
       * @brief Create a polynomial from bytes according to ISO Section 8.1 step 1 and 2.
       */
      Classic_McEliece_Polynomial create_element_from_bytes(std::span<const uint8_t> bytes) const;

      /// Represents F(y) by storing the non-zero terms
      std::vector<Big_F_Coefficient> m_position_map;

      /// t in spec, i.e., degree of F(y)
      size_t m_t;

      // f(z) in spec
      CmceGfMod m_poly_f;
};

bool operator==(const Classic_McEliece_Polynomial_Ring::Big_F_Coefficient& lhs,
                const Classic_McEliece_Polynomial_Ring::Big_F_Coefficient& rhs);

}  // namespace Botan
#endif
