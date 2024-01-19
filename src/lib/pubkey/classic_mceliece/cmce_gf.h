/*
 * Classic McEliece GF arithmetic
 * (C) 2023 Jack Lloyd
 *     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_CMCE_GF_H_
#define BOTAN_CMCE_GF_H_

#include <botan/assert.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/cmce_types.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/stl_util.h>

namespace Botan {

/**
 * @brief Represents an element of the finite field GF(q) for q = 2^m.
 *
 * This class implements the finite field GF(q) for q = 2^m via the irreducible
 * polynomial f(z) of degree m. The elements of GF(q) are represented as polynomials
 * of degree m-1 with coefficients in GF(2). Each element and the modulus is
 * represented by a uint16_t, where the i-th least significant bit corresponds to
 * the coefficient of z^i. For example, the element (z^3 + z^2 + 1) is represented
 * by the uint16_t 0b1101.
 */
class BOTAN_TEST_API Classic_McEliece_GF {
   public:
      /**
       * @brief Creates an element of GF(q) from a uint16_t.
       *
       * Each element and the modulus is represented by a uint16_t, where the i-th least significant bit
       * corresponds to the coefficient of z^i.
       *
       * @param elem The element as a uint16_t. Must be less than 2^m.
       * @param modulus The modulus of GF(q).
       */
      Classic_McEliece_GF(CmceGfElem elem, CmceGfMod modulus) : m_elem(elem), m_modulus(modulus) {
         BOTAN_DEBUG_ASSERT(elem <= (size_t(1) << log_q()) - 1);
      }

      /**
       * @brief Get m.
       *
       * For a given irreducible polynomial @p modulus f(z) representing the modulus of a finite field GF(q) = GF(2^m),
       * get the degree log_q of f(z) which corresponds to m.
       *
       * @param modulus The modulus of GF(q).
       * @return size_t The degree log_q of the modulus (m for GF(2^m)).
       */
      static size_t log_q_from_mod(CmceGfMod modulus) { return floor_log2(modulus.get()); }

      /**
       * @brief Get m, the degree of the element's modulus.
       *
       * @return size_t The degree log_q of the modulus (m for GF(2^m)).
       */
      size_t log_q() const { return log_q_from_mod(m_modulus); }

      /**
       * @brief Get the GF(q) element as a GF_Elem.
       *
       * @return the element as a GF_Elem.
       */
      CmceGfElem elem() const { return m_elem; }

      /**
       * @brief Get the modulus f(z) of GF(q) as a GF_Mod.
       *
       * @return the modulus as a GF_Mod.
       */
      CmceGfMod modulus() const { return m_modulus; }

      /**
       * @brief Change the element to @p elem.
       */
      Classic_McEliece_GF& operator=(const CmceGfElem elem) {
         m_elem = elem & CmceGfElem((size_t(1) << log_q()) - 1);
         return *this;
      }

      /**
       * @brief Divide the element by @p other in GF(q). Constant time.
       */
      Classic_McEliece_GF operator/(Classic_McEliece_GF other) const {
         BOTAN_DEBUG_ASSERT(m_modulus == other.m_modulus);
         return *this * other.inv();
      }

      /**
       * @brief Add @p other to the element. Constant time.
       */
      Classic_McEliece_GF operator+(Classic_McEliece_GF other) const {
         BOTAN_DEBUG_ASSERT(m_modulus == other.m_modulus);
         return Classic_McEliece_GF(m_elem ^ other.m_elem, m_modulus);
      }

      /**
       * @brief Add @p other to the element. Constant time.
       */
      Classic_McEliece_GF& operator+=(Classic_McEliece_GF other) {
         BOTAN_DEBUG_ASSERT(m_modulus == other.m_modulus);
         m_elem ^= other.m_elem;
         return *this;
      }

      /**
       * @brief Multiply the element by @p other in GF(q). Constant time.
       */
      Classic_McEliece_GF& operator*=(Classic_McEliece_GF other) {
         BOTAN_DEBUG_ASSERT(m_modulus == other.m_modulus);
         *this = *this * other;
         return *this;
      }

      /**
       * @brief Multiply the element by @p other in GF(q). Constant time.
       */
      Classic_McEliece_GF operator*(Classic_McEliece_GF other) const;

      /**
       * @brief Check if the element is equal to @p other. Modulus is ignored.
       */
      bool operator==(Classic_McEliece_GF other) const { return elem() == other.elem(); }

      /**
       * @brief Square the element. Constant time.
       */
      Classic_McEliece_GF square() const { return (*this) * (*this); }

      /**
       * @brief Invert the element. Constant time.
       */
      Classic_McEliece_GF inv() const;

      /**
      * @brief Check if the element is zero.
      */
      bool is_zero() const { return elem() == 0; }

   private:
      CmceGfElem m_elem;

      CmceGfMod m_modulus;
};

/**
 * @brief Constant time mask wrapper for GF(q) elements.
 */
class BOTAN_TEST_API GF_Mask final {
   public:
      template <std::unsigned_integral T>
      static GF_Mask expand(T v) {
         return GF_Mask(CT::Mask<uint16_t>::expand(v));
      }

      static GF_Mask expand(Classic_McEliece_GF v) { return expand(v.elem().get()); }

      static GF_Mask is_zero(Classic_McEliece_GF v) { return GF_Mask(CT::Mask<uint16_t>::is_zero(v.elem().get())); }

      static GF_Mask is_lte(Classic_McEliece_GF a, Classic_McEliece_GF b) {
         return GF_Mask(CT::Mask<uint16_t>::is_lte(a.elem().get(), b.elem().get()));
      }

      static GF_Mask is_equal(Classic_McEliece_GF a, Classic_McEliece_GF b) {
         return GF_Mask(CT::Mask<uint16_t>::is_equal(a.elem().get(), b.elem().get()));
      }

      static GF_Mask set() { return GF_Mask(CT::Mask<uint16_t>::set()); }

      GF_Mask(CT::Mask<uint16_t> underlying_mask) : m_mask(underlying_mask) {}

      Classic_McEliece_GF if_set_return(const Classic_McEliece_GF x) const {
         return Classic_McEliece_GF(CmceGfElem(m_mask.if_set_return(x.elem().get())), x.modulus());
      }

      Classic_McEliece_GF select(const Classic_McEliece_GF x, const Classic_McEliece_GF y) const {
         return Classic_McEliece_GF(CmceGfElem(m_mask.select(x.elem().get(), y.elem().get())), x.modulus());
      }

      Classic_McEliece_GF select(const Classic_McEliece_GF x, CmceGfElem y) const {
         return Classic_McEliece_GF(CmceGfElem(m_mask.select(x.elem().get(), y.get())), x.modulus());
      }

      uint16_t select(uint16_t x, uint16_t y) const { return m_mask.select(x, y); }

      GF_Mask& operator&=(const GF_Mask& o) {
         m_mask &= o.m_mask;
         return (*this);
      }

      bool as_bool() const { return m_mask.as_bool(); }

      CT::Mask<uint16_t>& elem_mask() { return m_mask; }

   private:
      CT::Mask<uint16_t> m_mask;
};

}  // namespace Botan
#endif
