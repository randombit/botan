/*
 * Classic McEliece Field Ordering Generation
 * Based on the public domain reference implementation by the designers
 * (https://classic.mceliece.org/impl.html - released in Oct 2022 for NISTPQC-R4)
 *
 * (C) 2023 Jack Lloyd
 *     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/
#include <botan/internal/cmce_field_ordering.h>

#include <botan/cmce.h>
#include <botan/mem_ops.h>
#include <botan/internal/loadstor.h>

#include <numeric>
#include <utility>
#include <vector>

namespace Botan {

namespace CMCE_CT {

namespace {

template <std::unsigned_integral T1, std::unsigned_integral T2>
   requires(sizeof(T1) <= 8 && sizeof(T2) <= 8)
void cond_swap_pair(CT::Mask<uint64_t> cond_mask, std::pair<T1, T2>& a, std::pair<T1, T2>& b) {
   cond_mask.conditional_swap(a.first, b.first);
   cond_mask.conditional_swap(a.second, b.second);
}

template <std::unsigned_integral T1, std::unsigned_integral T2>
void compare_and_swap_pair(std::span<std::pair<T1, T2>> a, size_t i, size_t k, size_t l) {
   static_assert(sizeof(T1) <= sizeof(uint64_t) && sizeof(T2) <= sizeof(uint64_t),
                 "Types T1 and T2 must be at most 64 bits wide");
   if((i & k) == 0) {  // i and k do not depend on secret data
      auto swap_required_mask = CT::Mask<uint64_t>::is_lt(a[l].first, a[i].first);
      cond_swap_pair(swap_required_mask, a[i], a[l]);
   } else {
      auto swap_required_mask = CT::Mask<uint64_t>::is_gt(a[l].first, a[i].first);
      cond_swap_pair(swap_required_mask, a[i], a[l]);
   }
}

// Sorts a vector of pairs after the first element
template <std::unsigned_integral T1, std::unsigned_integral T2>
void bitonic_sort_pair(std::span<std::pair<T1, T2>> a) {
   const size_t n = a.size();
   BOTAN_ARG_CHECK(is_power_of_2(n), "Input vector size must be a power of 2");

   for(size_t k = 2; k <= n; k *= 2) {
      for(size_t j = k / 2; j > 0; j /= 2) {
         for(size_t i = 0; i < n; ++i) {
            const size_t l = i ^ j;
            if(l > i) {
               compare_and_swap_pair(a, i, k, l);
            }
         }
      }
   }
}

template <std::unsigned_integral T>
T min(const T& a, const T& b) {
   auto mask = CT::Mask<T>::is_lt(a, b);
   return mask.select(a, b);
}

}  // namespace

}  // namespace CMCE_CT

namespace {
template <std::unsigned_integral T1, std::unsigned_integral T2>
std::vector<std::pair<T1, T2>> zip(std::span<const T1> vec_1, std::span<const T2> vec_2) {
   BOTAN_ARG_CHECK(vec_1.size() == vec_2.size(), "Vectors' dimensions do not match");
   std::vector<std::pair<T1, T2>> vec_zipped;
   vec_zipped.reserve(vec_1.size());
   for(size_t i = 0; i < vec_1.size(); ++i) {
      vec_zipped.push_back(std::make_pair(vec_1[i], vec_2[i]));
   }
   return vec_zipped;
}

template <std::unsigned_integral T1, std::unsigned_integral T2>
std::pair<secure_vector<T1>, secure_vector<T2>> unzip(const std::span<std::pair<T1, T2>>& vec_zipped) {
   std::pair<secure_vector<T1>, secure_vector<T2>> res;

   res.first.reserve(vec_zipped.size());
   res.second.reserve(vec_zipped.size());

   for(const auto& [elem1, elem2] : vec_zipped) {
      res.first.push_back(elem1);
      res.second.push_back(elem2);
   }
   return res;
}

/// @returns (vec[0],0), ..., (vec[n-1],n-1)
std::vector<std::pair<uint32_t, uint16_t>> enumerate(std::span<const uint32_t> vec) {
   BOTAN_DEBUG_ASSERT(vec.size() < std::numeric_limits<uint16_t>::max());

   std::vector<std::pair<uint32_t, uint16_t>> enumerated;

   std::transform(vec.begin(), vec.end(), std::back_inserter(enumerated), [ctr = uint16_t(0)](uint32_t elem) mutable {
      return std::make_pair(elem, ctr++);
   });

   return enumerated;
}

/**
 * @brief Create permutation pi as in (Section 8.2, Step 3).
 *
 * @param a The vector that is sorted
 *
 * @return (pi sorted after a, a sorted after pi)
 */
std::pair<secure_vector<uint32_t>, CmcePermutation> create_pi(secure_vector<uint32_t> a) {
   auto a_pi_zipped = enumerate(a);
   CMCE_CT::bitonic_sort_pair(std::span(a_pi_zipped));

   CmcePermutation pi_sorted;
   std::tie(a, pi_sorted.get()) = unzip(std::span(a_pi_zipped));

   return std::make_pair(a, pi_sorted);
}

/**
* @brief Create a GF element from pi as in (Section 8.2, Step 4).
* Corresponds to the reverse bits of pi.
*/
Classic_McEliece_GF from_pi(CmcePermutationElement pi_elem, CmceGfMod modulus, size_t m) {
   auto reversed_bits = ct_reverse_bits(pi_elem.get());
   reversed_bits >>= (sizeof(uint16_t) * 8 - m);
   return Classic_McEliece_GF(CmceGfElem(reversed_bits), modulus);
}

/**
 * @brief Part of field ordering generation according to ISO 9.2.10
 */
secure_vector<uint16_t> composeinv(std::span<const uint16_t> c, std::span<const uint16_t> pi) {
   auto pi_c_zipped = zip(pi, c);
   CMCE_CT::bitonic_sort_pair(std::span(pi_c_zipped));
   // Extract c from the sorted vector
   secure_vector<uint16_t> c_sorted;
   std::transform(pi_c_zipped.begin(), pi_c_zipped.end(), std::back_inserter(c_sorted), [](const auto& pair) {
      return pair.second;
   });

   return c_sorted;
}

// p,q = composeinv(p,q),composeinv(q,p)
void simultaneous_composeinv(secure_vector<uint16_t>& p, secure_vector<uint16_t>& q) {
   auto p_new = composeinv(p, q);
   q = composeinv(q, p);
   p = std::move(p_new);
}

/**
 * @brief Generate control bits as in ISO 9.2.10.
 *
 * TODO: This function can be optimized (see Classic McEliece reference implementation)
 */
secure_vector<uint16_t> generate_control_bits_internal(const secure_vector<uint16_t>& pi) {
   const auto n = pi.size();
   BOTAN_ASSERT_NOMSG(is_power_of_2(n));
   const size_t m = ceil_log2(n);

   if(m == 1) {
      return secure_vector<uint16_t>({pi.at(0)});
   }
   secure_vector<uint16_t> p(n);
   for(size_t x = 0; x < n; ++x) {
      p.at(x) = pi.at(x ^ 1);
   }
   secure_vector<uint16_t> q(n);
   for(size_t x = 0; x < n; ++x) {
      q.at(x) = pi.at(x) ^ 1;
   }

   secure_vector<uint16_t> range_n(n);
   std::iota(range_n.begin(), range_n.end(), static_cast<uint16_t>(0));
   auto piinv = composeinv(range_n, pi);

   simultaneous_composeinv(p, q);

   secure_vector<uint16_t> c(n);
   for(uint16_t x = 0; static_cast<size_t>(x) < n; ++x) {
      c.at(x) = CMCE_CT::min(x, p.at(x));
   }

   simultaneous_composeinv(p, q);

   for(size_t i = 1; i < m - 1; ++i) {
      auto cp = composeinv(c, q);
      simultaneous_composeinv(p, q);
      for(size_t x = 0; x < n; ++x) {
         c.at(x) = CMCE_CT::min(c.at(x), cp.at(x));
      }
   }

   secure_vector<uint16_t> f(n / 2);
   for(size_t j = 0; j < n / 2; ++j) {
      f.at(j) = c.at(2 * j) % 2;
   }

   secure_vector<uint16_t> big_f(n);
   for(uint16_t x = 0; size_t(x) < n; ++x) {
      big_f.at(x) = x ^ f.at(x / 2);
   }

   auto fpi = composeinv(big_f, piinv);

   secure_vector<uint16_t> l(n / 2);
   for(size_t k = 0; k < n / 2; ++k) {
      l.at(k) = fpi.at(2 * k) % 2;
   }

   secure_vector<uint16_t> big_l(n);
   for(uint16_t y = 0; size_t(y) < n; ++y) {
      big_l.at(y) = y ^ l.at(y / 2);
   }

   auto big_m = composeinv(fpi, big_l);

   secure_vector<uint16_t> subm0(n / 2);
   secure_vector<uint16_t> subm1(n / 2);
   for(size_t j = 0; j < n / 2; ++j) {
      subm0.at(j) = big_m.at(2 * j) / 2;
      subm1.at(j) = big_m.at(2 * j + 1) / 2;
   }

   auto subz0 = generate_control_bits_internal(subm0);
   auto subz1 = generate_control_bits_internal(subm1);

   secure_vector<uint16_t> z(subz0.size() + subz1.size());
   for(size_t j = 0; j < subz0.size(); ++j) {
      z.at(2 * j) = subz0.at(j);
      z.at(2 * j + 1) = subz1.at(j);
   }

   return concat(f, z, l);
}

CT::Choice ct_has_adjacent_duplicates(std::span<const uint32_t> vec) {
   CT::Mask<uint32_t> mask = CT::Mask<uint32_t>::cleared();
   for(size_t i = 0; i < vec.size() - 1; ++i) {
      mask |= CT::Mask<uint32_t>::is_equal(vec[i], vec[i + 1]);
   }
   return mask.as_choice();
}

}  // anonymous namespace

std::optional<Classic_McEliece_Field_Ordering> Classic_McEliece_Field_Ordering::create_field_ordering(
   const Classic_McEliece_Parameters& params, StrongSpan<const CmceOrderingBits> random_bits) {
   BOTAN_ARG_CHECK(random_bits.size() == (params.sigma2() * params.q()) / 8, "Wrong random bits size");

   auto a = load_le<secure_vector<uint32_t>>(random_bits);  // contains a_0, a_1, ...
   auto [sorted_a, pi] = create_pi(std::move(a));
   if(ct_has_adjacent_duplicates(sorted_a).as_bool()) {
      return std::nullopt;
   }

   return Classic_McEliece_Field_Ordering(std::move(pi), params.poly_f());
}

std::vector<Classic_McEliece_GF> Classic_McEliece_Field_Ordering::alphas(size_t n) const {
   BOTAN_ASSERT_NOMSG(m_poly_f.get() != 0);
   BOTAN_ASSERT_NOMSG(m_pi.size() >= n);

   std::vector<Classic_McEliece_GF> n_alphas_vec;

   std::transform(m_pi.begin(), m_pi.begin() + n, std::back_inserter(n_alphas_vec), [this](uint16_t pi_elem) {
      return from_pi(CmcePermutationElement(pi_elem), m_poly_f, Classic_McEliece_GF::log_q_from_mod(m_poly_f));
   });

   return n_alphas_vec;
}

secure_bitvector Classic_McEliece_Field_Ordering::alphas_control_bits() const {
   // Each vector element contains one bit of the control bits
   const auto control_bits_as_words = generate_control_bits_internal(m_pi.get());
   auto control_bits = secure_bitvector(control_bits_as_words.size());
   for(size_t i = 0; i < control_bits.size(); ++i) {
      control_bits.at(i) = control_bits_as_words.at(i);
   }

   return control_bits;
}

// Based on the Python code "permutation(c)" from Bernstein
// "Verified fast formulas for control bits for permutation networks"
Classic_McEliece_Field_Ordering Classic_McEliece_Field_Ordering::create_from_control_bits(
   const Classic_McEliece_Parameters& params, const secure_bitvector& control_bits) {
   BOTAN_ASSERT_NOMSG(control_bits.size() == (2 * params.m() - 1) << (params.m() - 1));
   const uint16_t n = uint16_t(1) << params.m();
   CmcePermutation pi(n);
   std::iota(pi.begin(), pi.end(), static_cast<uint16_t>(0));
   for(size_t i = 0; i < 2 * params.m() - 1; ++i) {
      const size_t gap = size_t(1) << std::min(i, 2 * params.m() - 2 - i);
      for(size_t j = 0; j < size_t(n / 2); ++j) {
         const size_t pos = (j % gap) + 2 * gap * (j / gap);
         auto mask = CT::Mask<uint16_t>::expand(control_bits[i * n / 2 + j]);
         mask.conditional_swap(pi[pos], pi[pos + gap]);
      }
   }

   return Classic_McEliece_Field_Ordering(std::move(pi), params.poly_f());
}

void Classic_McEliece_Field_Ordering::permute_with_pivots(const Classic_McEliece_Parameters& params,
                                                          const CmceColumnSelection& pivots) {
   auto col_offset = params.pk_no_rows() - Classic_McEliece_Parameters::mu();

   for(size_t p_idx = 1; p_idx <= Classic_McEliece_Parameters::mu(); ++p_idx) {
      size_t p_counter = 0;
      for(size_t col = 0; col < Classic_McEliece_Parameters::nu(); ++col) {
         auto mask_is_pivot_set = CT::Mask<size_t>::expand(pivots.at(col));
         p_counter += CT::Mask<size_t>::expand(pivots.at(col)).if_set_return(1);
         auto mask_is_current_pivot = CT::Mask<size_t>::is_equal(p_idx, p_counter);
         (mask_is_pivot_set & mask_is_current_pivot)
            .conditional_swap(m_pi.get().at(col_offset + col), m_pi.get().at(col_offset + p_idx - 1));
      }
   }
}

}  // namespace Botan
