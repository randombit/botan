/*
 * (C) Copyright Projet SECRET, INRIA, Rocquencourt
 * (C) Bhaskar Biswas and  Nicolas Sendrier
 *
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 *
 */

#ifndef BOTAN_POLYN_GF2M_H_
#define BOTAN_POLYN_GF2M_H_

#include <botan/secmem.h>
#include <utility>

namespace Botan {

typedef uint16_t gf2m;

class GF2m_Field;

class RandomNumberGenerator;

class polyn_gf2m {
   public:
      /**
      * create a zero polynomial:
      */
      explicit polyn_gf2m(const std::shared_ptr<GF2m_Field>& sp_field);

      polyn_gf2m() : m_deg(-1) {}

      polyn_gf2m(const secure_vector<uint8_t>& encoded, const std::shared_ptr<GF2m_Field>& sp_field);

      polyn_gf2m& operator=(const polyn_gf2m&) = default;

      /**
      * create zero polynomial with reservation of space for a degree d polynomial
      */
      polyn_gf2m(int d, const std::shared_ptr<GF2m_Field>& sp_field);

      polyn_gf2m(const polyn_gf2m& other);

      /**
      * random irreducible polynomial of degree t
      */
      polyn_gf2m(size_t t, RandomNumberGenerator& rng, const std::shared_ptr<GF2m_Field>& sp_field);

      /** decode a polynomial from memory: **/
      polyn_gf2m(const uint8_t* mem, uint32_t mem_len, const std::shared_ptr<GF2m_Field>& sp_field);

      /**
      *  create a polynomial from memory area (encoded)
      */
      polyn_gf2m(int degree, const uint8_t* mem, size_t mem_byte_len, const std::shared_ptr<GF2m_Field>& sp_field);

      bool operator==(const polyn_gf2m& other) const;

      bool operator!=(const polyn_gf2m& other) const { return !(*this == other); }

      polyn_gf2m(polyn_gf2m&& other) noexcept { this->swap(other); }

      polyn_gf2m& operator=(polyn_gf2m&& other) noexcept {
         if(this != &other) {
            this->swap(other);
         }
         return *this;
      }

      void swap(polyn_gf2m& other) noexcept;

      secure_vector<uint8_t> encode() const;

      std::shared_ptr<GF2m_Field> get_sp_field() const { return m_sp_field; }

      gf2m& operator[](size_t i) { return m_coeff[i]; }

      gf2m operator[](size_t i) const { return m_coeff[i]; }

      gf2m get_lead_coef() const { return m_coeff[m_deg]; }

      gf2m get_coef(size_t i) const { return m_coeff[i]; }

      inline void set_coef(size_t i, gf2m v) { m_coeff[i] = v; }

      inline void add_to_coef(size_t i, gf2m v) { m_coeff[i] ^= v; }

      void encode(uint32_t min_numo_coeffs, uint8_t* mem, uint32_t mem_len) const;

      int get_degree() const;

      /**
      * determine the degree in a timing secure manner. the timing of this function
      * only depends on the number of allocated coefficients, not on the actual
      * degree
      */
      int calc_degree_secure() const;

      static size_t degppf(const polyn_gf2m& g);

      static std::vector<polyn_gf2m> sqmod_init(const polyn_gf2m& g);

      static std::vector<polyn_gf2m> sqrt_mod_init(const polyn_gf2m& g);

      polyn_gf2m sqmod(const std::vector<polyn_gf2m>& sq, int d);
      void set_to_zero();
      gf2m eval(gf2m a);

      static std::pair<polyn_gf2m, polyn_gf2m> eea_with_coefficients(const polyn_gf2m& p,
                                                                     const polyn_gf2m& g,
                                                                     int break_deg);

      void patchup_deg_secure(uint32_t trgt_deg, gf2m patch_elem);

   private:
      void set_degree(int d) { m_deg = d; }

      void poly_shiftmod(const polyn_gf2m& g);
      void realloc(uint32_t new_size);
      static polyn_gf2m gcd(const polyn_gf2m& p1, const polyn_gf2m& p2);

      /**
      * destructive:
      */
      static void remainder(polyn_gf2m& p, const polyn_gf2m& g);

      static polyn_gf2m gcd_aux(polyn_gf2m& p1, polyn_gf2m& p2);

   private:
      int m_deg;
      secure_vector<gf2m> m_coeff;
      std::shared_ptr<GF2m_Field> m_sp_field;
};

gf2m random_gf2m(RandomNumberGenerator& rng);
gf2m random_code_element(uint16_t code_length, RandomNumberGenerator& rng);

std::vector<polyn_gf2m> syndrome_init(const polyn_gf2m& generator, const std::vector<gf2m>& support, int n);

/**
* Find the roots of a polynomial over GF(2^m) using the method by Federenko et al.
*/
secure_vector<gf2m> find_roots_gf2m_decomp(const polyn_gf2m& polyn, size_t code_length);

}  // namespace Botan

#endif
