/*
 * PQ CRYSTALS Common Structures
 *
 * Further changes
 * (C) 2021-2024 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2024 René Meusel, Fabian Albert, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_PQ_CRYSTALS_H_
#define BOTAN_PQ_CRYSTALS_H_

#include <concepts>
#include <limits>
#include <span>
#include <vector>

#include <botan/assert.h>
#include <botan/mem_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/pqcrystals_helpers.h>

namespace Botan::CRYSTALS {

enum class Domain { Normal, NTT };

template <typename T>
concept crystals_constants =
   std::signed_integral<typename T::T> && std::integral<decltype(T::N)> && std::integral<decltype(T::Q)> &&
   std::integral<decltype(T::F)> && std::unsigned_integral<decltype(T::NTT_Degree)> &&
   std::integral<decltype(T::ROOT_OF_UNITY)>;

/**
 * This implements basic polynomial operations for Kyber and Dilithium
 * based on the given algorithm constants (@p ConstantsT) and back-
 * references some of the operations to the actual implementation
 * into the derived class (CRTP @p DerivedT).
 *
 * Polynomial parameters are passed as spans of coefficients for maximum
 * flexibility.
 *
 * It is assumed that this is subclassed with the actual implementation
 * with establishing a CRTP back-reference.
 */
template <crystals_constants ConstantsT, typename DerivedT>
class Trait_Base {
   public:
      using T = typename ConstantsT::T;
      static constexpr T N = ConstantsT::N;
      static constexpr T Q = ConstantsT::Q;

   protected:
      using T2 = next_longer_int_t<T>;

      /// \name Pre-computed algorithm constants
      /// @{

      static constexpr T Q_inverse = modular_inverse(Q);
      static constexpr T MONTY = montgomery_R(Q);
      static constexpr T MONTY_SQUARED = montgomery_R2(Q);

      // Contains the constant f from Algorithm 36 multiplied two times by
      // the montgomery parameter, i.e. 2^(2*32) mod q. The first montgomery
      // factor is then removed by the reduction in the loop. The second one
      // is required to eliminate factors 2^(-32) mod q in coeffs introduced
      // by previous montgomery multiplications in a single vector/matrix
      // multiplication operation.
      static constexpr T F_WITH_MONTY_SQUARED = (static_cast<T2>(ConstantsT::F) * MONTY_SQUARED) % Q;

      static constexpr auto zetas = precompute_zetas<ConstantsT::NTT_Degree>(Q, MONTY, ConstantsT::ROOT_OF_UNITY);

      /// @}

   protected:
      /// @returns the number of polynomials in the polynomial vector @p polyvec.
      static constexpr size_t polys_in_polyvec(std::span<const T> polyvec) {
         BOTAN_DEBUG_ASSERT(polyvec.size() % N == 0);
         return polyvec.size() / N;
      }

      /// @returns the @p index-th polynomial in the polynomial vector @p polyvec.
      template <typename U>
         requires(std::same_as<T, U> || std::same_as<const T, U>)
      static constexpr std::span<U, N> poly_in_polyvec(std::span<U> polyvec, size_t index) {
         BOTAN_DEBUG_ASSERT(polyvec.size() % N == 0);
         BOTAN_DEBUG_ASSERT(polyvec.size() / N > index);
         auto polyspan = polyvec.subspan(index * N, N);
         return std::span<U, N>{polyspan.data(), polyspan.size()};
      }

      static constexpr T fqmul(T a, T b) { return DerivedT::montgomery_reduce_coefficient(static_cast<T2>(a) * b); }

   public:
      static constexpr void poly_add(std::span<T, N> result, std::span<const T, N> lhs, std::span<const T, N> rhs) {
         for(size_t i = 0; i < N; ++i) {
            result[i] = lhs[i] + rhs[i];
         }
      }

      static constexpr void poly_sub(std::span<T, N> result, std::span<const T, N> lhs, std::span<const T, N> rhs) {
         for(size_t i = 0; i < N; ++i) {
            result[i] = lhs[i] - rhs[i];
         }
      }

      /// Adds Q if the coefficient is negative.
      static constexpr void poly_cadd_q(std::span<T, N> coeffs) {
         for(auto& coeff : coeffs) {
            using unsigned_T = std::make_unsigned_t<T>;
            const auto is_negative = CT::Mask<unsigned_T>::expand_top_bit(static_cast<unsigned_T>(coeff));
            coeff += is_negative.if_set_return(Q);
         }
      }

      static constexpr T to_montgomery(T a) { return fqmul(a, MONTY_SQUARED); }

      constexpr static void barrett_reduce(std::span<T, N> poly) {
         for(auto& coeff : poly) {
            coeff = DerivedT::barrett_reduce_coefficient(coeff);
         }
      }

      /// Multiplication and accumulation of 2 polynomial vectors @p u and @p v.
      static constexpr void polyvec_pointwise_acc_montgomery(std::span<T, N> w,
                                                             std::span<const T> u,
                                                             std::span<const T> v) {
         clear_mem(w);
         std::array<T, N> t;
         for(size_t i = 0; i < polys_in_polyvec(u); ++i) {
            DerivedT::poly_pointwise_montgomery(t, poly_in_polyvec(u, i), poly_in_polyvec(v, i));
            poly_add(w, w, t);
         }
         barrett_reduce(w);
      }
};

template <typename T>
concept crystals_trait =
   std::signed_integral<typename T::T> && sizeof(typename T::T) <= 4 && std::integral<decltype(T::N)> &&
   T::N % 2 == 0 &&
   requires(std::span<typename T::T, T::N> polyspan, std::span<typename T::T> polyvecspan, typename T::T coeff) {
      { T::to_montgomery(coeff) };
      { T::barrett_reduce(polyspan) };
      { T::poly_cadd_q(polyspan) };
      { T::ntt(polyspan) };
      { T::inverse_ntt(polyspan) };
      { T::poly_pointwise_montgomery(polyspan, polyspan, polyspan) };
      { T::polyvec_pointwise_acc_montgomery(polyspan, polyvecspan, polyvecspan) };
   };

namespace detail {

/**
 * Converts polynomials or polynomial vectors from one domain to another.
 */
template <Domain To, template <typename, Domain> class StructureT, crystals_trait Trait, Domain From>
   requires(To != From)
StructureT<Trait, To> domain_cast(StructureT<Trait, From>&& p) {
   // The public factory method `from_domain_cast` is just a workaround for
   // Xcode and NDK not understanding the friend declaration to allow this
   // to directly call the private constructor.
   return StructureT<Trait, To>::from_domain_cast(std::move(p));
}

/**
 * Ensures that all values in the @p range are within the range [min, max]
 * using constant-time operations.
 *
 * @returns true if all values are within the range, false otherwise.
 */
template <std::integral T, size_t N = std::dynamic_extent>
constexpr static bool ct_all_within_range(std::span<const T, N> range, T min, T max)
   requires(sizeof(T) <= 4)
{
   BOTAN_DEBUG_ASSERT(min < max);

   using unsigned_T = std::make_unsigned_t<T>;
   auto map = [](T v) -> unsigned_T {
      if constexpr(std::signed_integral<T>) {
         constexpr int64_t offset = -static_cast<int64_t>(std::numeric_limits<T>::min());
         return static_cast<unsigned_T>(static_cast<int64_t>(v) + offset);
      } else {
         return v;
      }
   };

   const auto umin = map(min);
   const auto umax = map(max);

   auto mask = CT::Mask<unsigned_T>::set();
   for(const T c : range) {
      mask &= CT::Mask<unsigned_T>::is_within_range(map(c), umin, umax);
   }
   return mask.as_bool();
}

}  // namespace detail

/**
 * Represents a polynomial with Trait::N coefficients of type Trait::T.
 * The domain of the polynomial can be either Domain::Normal or Domain::NTT and
 * this information is represented in the C++ type system.
 *
 * Polynomials may either own their storage of piggy-back on external storage
 * when they are part of a PolynomialVector.
 */
template <crystals_trait Trait, Domain D = Domain::Normal>
class Polynomial {
   private:
      using ThisPolynomial = Polynomial<Trait, D>;
      using T = typename Trait::T;

   private:
      // TODO: perhaps secure vector
      std::vector<T> m_coeffs_storage;
      std::span<T, Trait::N> m_coeffs;

   private:
      template <crystals_trait OtherTrait, Domain OtherD>
      friend class Polynomial;

      template <Domain To, template <typename, Domain> class StructureT, crystals_trait C, Domain From>
         requires(To != From)
      friend StructureT<C, To> detail::domain_cast(StructureT<C, From>&&);

      /**
       * This constructor is used to convert a Polynomial from one domain to another.
       * The friend declarations above facilitate this.
       */
      template <Domain OtherD>
         requires(D != OtherD)
      explicit Polynomial(Polynomial<Trait, OtherD>&& other) noexcept :
            m_coeffs_storage(std::move(other.m_coeffs_storage)),
            m_coeffs(owns_storage() ? std::span<T, Trait::N>(m_coeffs_storage) : other.m_coeffs) {}

   public:
      // Workaround, because Xcode and NDK don't understand the
      // `detail::domain_cast` friend declaration.
      //
      // TODO: Try to remove this and use the c'tor directly in
      //       `detail::domain_cast` after updating the compilers.
      template <Domain OtherD>
         requires(D != OtherD)
      static Polynomial<Trait, D> from_domain_cast(Polynomial<Trait, OtherD>&& p) {
         return Polynomial<Trait, D>(std::move(p));
      }

   public:
      Polynomial() : m_coeffs_storage(Trait::N), m_coeffs(m_coeffs_storage) { BOTAN_DEBUG_ASSERT(owns_storage()); }

      explicit Polynomial(std::span<T, Trait::N> coeffs) : m_coeffs(coeffs) { BOTAN_DEBUG_ASSERT(!owns_storage()); }

      Polynomial(const ThisPolynomial& other) = delete;

      Polynomial(ThisPolynomial&& other) noexcept :
            m_coeffs_storage(std::move(other.m_coeffs_storage)), m_coeffs(other.m_coeffs) {}

      ThisPolynomial& operator=(const ThisPolynomial& other) = delete;

      ThisPolynomial& operator=(ThisPolynomial&& other) noexcept {
         if(this != &other) {
            BOTAN_ASSERT_NOMSG(owns_storage());
            m_coeffs_storage = std::move(other.m_coeffs_storage);
            m_coeffs = std::span<T, Trait::N>(m_coeffs_storage);
         }
         return *this;
      }

      ~Polynomial() = default;

      constexpr size_t size() const { return m_coeffs.size(); }

      constexpr Domain domain() const noexcept { return D; }

      ThisPolynomial clone() const {
         ThisPolynomial res;
         copy_mem(res.m_coeffs_storage, m_coeffs);
         res.m_coeffs = std::span<T, Trait::N>(res.m_coeffs_storage);
         BOTAN_DEBUG_ASSERT(res.owns_storage());
         return res;
      }

      /// @returns true if all coefficients are within the range [min, max]
      constexpr bool ct_validate_value_range(T min, T max) const noexcept {
         return detail::ct_all_within_range(coefficients(), min, max);
      }

      /// @returns the number of non-zero coefficients in the polynomial
      constexpr size_t hamming_weight() const noexcept {
         size_t weight = 0;
         for(const auto c : m_coeffs) {
            weight += (c != 0);
         }
         return weight;
      }

      std::span<T, Trait::N> coefficients() { return m_coeffs; }

      std::span<const T, Trait::N> coefficients() const { return m_coeffs; }

      T& operator[](size_t i) { return m_coeffs[i]; }

      T operator[](size_t i) const { return m_coeffs[i]; }

      decltype(auto) begin() { return m_coeffs.begin(); }

      decltype(auto) begin() const { return m_coeffs.begin(); }

      decltype(auto) end() { return m_coeffs.end(); }

      decltype(auto) end() const { return m_coeffs.end(); }

      constexpr bool owns_storage() const { return !m_coeffs_storage.empty(); }

      ThisPolynomial& reduce() {
         Trait::barrett_reduce(m_coeffs);
         return *this;
      }

      ThisPolynomial& conditional_add_q() {
         Trait::poly_cadd_q(m_coeffs);
         return *this;
      }

      void _const_time_poison() const { CT::poison(m_coeffs); }

      void _const_time_unpoison() const { CT::unpoison(m_coeffs); }

      /**
       * Adds two polynomials element-wise. Does not perform a reduction after the addition.
       * Therefore this operation might cause an integer overflow.
       */
      decltype(auto) operator+=(const ThisPolynomial& other) {
         Trait::poly_add(m_coeffs, m_coeffs, other.m_coeffs);
         return *this;
      }

      /**
       * Subtracts two polynomials element-wise. Does not perform a reduction after the subtraction.
       * Therefore this operation might cause an integer underflow.
       */
      decltype(auto) operator-=(const ThisPolynomial& other) {
         Trait::poly_sub(m_coeffs, m_coeffs, other.m_coeffs);
         return *this;
      }
};

template <crystals_trait Trait, Domain D = Domain::Normal>
class PolynomialVector {
   private:
      using ThisPolynomialVector = PolynomialVector<Trait, D>;
      using T = typename Trait::T;

   private:
      std::vector<T> m_polys_storage;
      std::vector<Polynomial<Trait, D>> m_vec;

   private:
      template <crystals_trait OtherTrait, Domain OtherD>
      friend class PolynomialVector;

      template <Domain To, template <typename, Domain> class StructureT, crystals_trait C, Domain From>
         requires(To != From)
      friend StructureT<C, To> detail::domain_cast(StructureT<C, From>&&);

      /**
       * This constructor is used to convert a PolynomialVector from one domain to another.
       * The friend declarations above facilitate this.
       */
      template <Domain OtherD>
         requires(D != OtherD)
      explicit PolynomialVector(PolynomialVector<Trait, OtherD>&& other) noexcept :
            m_polys_storage(std::move(other.m_polys_storage)) {
         BOTAN_DEBUG_ASSERT(m_polys_storage.size() % Trait::N == 0);
         const size_t vecsize = m_polys_storage.size() / Trait::N;
         for(size_t i = 0; i < vecsize; ++i) {
            m_vec.emplace_back(
               Polynomial<Trait, D>(std::span{m_polys_storage}.subspan(i * Trait::N).template first<Trait::N>()));
         }
      }

   public:
      // Workaround, because Xcode and NDK don't understand the
      // `detail::domain_cast` friend declaration above.
      //
      // TODO: Try to remove this and use the c'tor directly in
      //       `detail::domain_cast` after updating the compilers.
      template <Domain OtherD>
         requires(D != OtherD)
      static PolynomialVector<Trait, D> from_domain_cast(PolynomialVector<Trait, OtherD>&& other) {
         return PolynomialVector<Trait, D>(std::move(other));
      }

   public:
      PolynomialVector(size_t vecsize) : m_polys_storage(vecsize * Trait::N) {
         for(size_t i = 0; i < vecsize; ++i) {
            m_vec.emplace_back(
               Polynomial<Trait, D>(std::span{m_polys_storage}.subspan(i * Trait::N).template first<Trait::N>()));
         }
      }

      PolynomialVector(const ThisPolynomialVector& other) = delete;
      PolynomialVector(ThisPolynomialVector&& other) noexcept = default;
      ThisPolynomialVector& operator=(const ThisPolynomialVector& other) = delete;
      ThisPolynomialVector& operator=(ThisPolynomialVector&& other) noexcept = default;
      ~PolynomialVector() = default;

      size_t size() const { return m_vec.size(); }

      constexpr Domain domain() const noexcept { return D; }

      ThisPolynomialVector clone() const {
         ThisPolynomialVector res(size());

         // The default-constructed PolynomialVector has set up res.m_vec to
         // point to res.m_polys_storage. Therefore we can just copy the data
         // into res.m_polys_storage to fill the non-owning polynomials.
         copy_mem(res.m_polys_storage, m_polys_storage);

         return res;
      }

      /// @returns the number of non-zero coefficients in the polynomial vector
      size_t hamming_weight() const noexcept {
         size_t weight = 0;
         for(const auto c : m_polys_storage) {
            weight += (c != 0);
         }
         return weight;
      }

      /// @returns true if all coefficients are within the range [min, max]
      constexpr bool ct_validate_value_range(T min, T max) const noexcept {
         return detail::ct_all_within_range(coefficients(), min, max);
      }

      std::span<T> coefficients() { return m_polys_storage; }

      std::span<const T> coefficients() const { return m_polys_storage; }

      ThisPolynomialVector& operator+=(const ThisPolynomialVector& other) {
         BOTAN_ASSERT(m_vec.size() == other.m_vec.size(), "cannot add polynomial vectors of differing lengths");
         for(size_t i = 0; i < m_vec.size(); ++i) {
            Trait::poly_add(m_vec[i].coefficients(), m_vec[i].coefficients(), other.m_vec[i].coefficients());
         }
         return *this;
      }

      ThisPolynomialVector& operator-=(const ThisPolynomialVector& other) {
         BOTAN_ASSERT(m_vec.size() == other.m_vec.size(), "cannot subtract polynomial vectors of differing lengths");
         for(size_t i = 0; i < m_vec.size(); ++i) {
            Trait::poly_sub(m_vec[i].coefficients(), m_vec[i].coefficients(), other.m_vec[i].coefficients());
         }
         return *this;
      }

      ThisPolynomialVector& reduce() {
         for(auto& p : m_vec) {
            Trait::barrett_reduce(p.coefficients());
         }
         return *this;
      }

      ThisPolynomialVector& conditional_add_q() {
         for(auto& v : m_vec) {
            Trait::poly_cadd_q(v.coefficients());
         }
         return *this;
      }

      Polynomial<Trait, D>& operator[](size_t i) { return m_vec[i]; }

      const Polynomial<Trait, D>& operator[](size_t i) const { return m_vec[i]; }

      decltype(auto) begin() { return m_vec.begin(); }

      decltype(auto) begin() const { return m_vec.begin(); }

      decltype(auto) end() { return m_vec.end(); }

      decltype(auto) end() const { return m_vec.end(); }

      void _const_time_poison() const { CT::poison_range(m_vec); }

      void _const_time_unpoison() const { CT::unpoison_range(m_vec); }
};

template <crystals_trait Trait>
class PolynomialMatrix {
   private:
      using ThisPolynomialMatrix = PolynomialMatrix<Trait>;

   private:
      std::vector<PolynomialVector<Trait, Domain::NTT>> m_mat;

   public:
      PolynomialMatrix(std::vector<PolynomialVector<Trait>> mat) : m_mat(std::move(mat)) {}

      PolynomialMatrix(const ThisPolynomialMatrix& other) = delete;
      PolynomialMatrix(ThisPolynomialMatrix&& other) noexcept = default;
      ThisPolynomialMatrix& operator=(const ThisPolynomialMatrix& other) = delete;
      ThisPolynomialMatrix& operator=(ThisPolynomialMatrix&& other) noexcept = default;
      ~PolynomialMatrix() = default;

      size_t size() const { return m_mat.size(); }

      PolynomialMatrix(size_t rows, size_t cols) {
         m_mat.reserve(rows);
         for(size_t i = 0; i < rows; ++i) {
            m_mat.emplace_back(cols);
         }
      }

      PolynomialVector<Trait, Domain::NTT>& operator[](size_t i) { return m_mat[i]; }

      const PolynomialVector<Trait, Domain::NTT>& operator[](size_t i) const { return m_mat[i]; }

      decltype(auto) begin() { return m_mat.begin(); }

      decltype(auto) begin() const { return m_mat.begin(); }

      decltype(auto) end() { return m_mat.end(); }

      decltype(auto) end() const { return m_mat.end(); }

      void _const_time_poison() const { CT::poison_range(m_mat); }

      void _const_time_unpoison() const { CT::unpoison_range(m_mat); }
};

namespace detail {

template <crystals_trait Trait, Domain D>
void montgomery(Polynomial<Trait, D>& p) {
   for(auto& c : p) {
      c = Trait::to_montgomery(c);
   }
}

template <crystals_trait Trait>
void dot_product(Polynomial<Trait, Domain::NTT>& out,
                 const PolynomialVector<Trait, Domain::NTT>& a,
                 const PolynomialVector<Trait, Domain::NTT>& b) {
   BOTAN_ASSERT(a.size() == b.size(), "Dot product requires equally sized PolynomialVectors");
   for(size_t i = 0; i < a.size(); ++i) {
      out += a[i] * b[i];
   }
   out.reduce();
}

}  // namespace detail

template <crystals_trait Trait>
Polynomial<Trait, Domain::NTT> ntt(Polynomial<Trait, Domain::Normal> p) {
   auto p_ntt = detail::domain_cast<Domain::NTT>(std::move(p));
   Trait::ntt(p_ntt.coefficients());
   return p_ntt;
}

template <crystals_trait Trait>
Polynomial<Trait, Domain::Normal> inverse_ntt(Polynomial<Trait, Domain::NTT> p_ntt) {
   auto p = detail::domain_cast<Domain::Normal>(std::move(p_ntt));
   Trait::inverse_ntt(p.coefficients());
   return p;
}

template <crystals_trait Trait>
PolynomialVector<Trait, Domain::NTT> ntt(PolynomialVector<Trait, Domain::Normal> polyvec) {
   auto polyvec_ntt = detail::domain_cast<Domain::NTT>(std::move(polyvec));
   for(auto& poly : polyvec_ntt) {
      Trait::ntt(poly.coefficients());
   }
   return polyvec_ntt;
}

template <crystals_trait Trait>
PolynomialVector<Trait, Domain::Normal> inverse_ntt(PolynomialVector<Trait, Domain::NTT> polyvec_ntt) {
   auto polyvec = detail::domain_cast<Domain::Normal>(std::move(polyvec_ntt));
   for(auto& poly : polyvec) {
      Trait::inverse_ntt(poly.coefficients());
   }
   return polyvec;
}

template <crystals_trait Trait, Domain D>
Polynomial<Trait, D> montgomery(Polynomial<Trait, D> p) {
   detail::montgomery(p);
   return p;
}

template <crystals_trait Trait, Domain D>
PolynomialVector<Trait, D> montgomery(PolynomialVector<Trait, D> polyvec) {
   for(auto& p : polyvec) {
      detail::montgomery(p);
   }
   return polyvec;
}

template <crystals_trait Trait>
PolynomialVector<Trait, Domain::Normal> operator+(const PolynomialVector<Trait, Domain::Normal>& a,
                                                  const PolynomialVector<Trait, Domain::Normal>& b) {
   BOTAN_DEBUG_ASSERT(a.size() == b.size());
   PolynomialVector<Trait, Domain::Normal> result(a.size());
   for(size_t i = 0; i < a.size(); ++i) {
      Trait::poly_add(result[i].coefficients(), a[i].coefficients(), b[i].coefficients());
   }
   return result;
}

template <crystals_trait Trait>
PolynomialVector<Trait, Domain::NTT> operator*(const PolynomialMatrix<Trait>& mat,
                                               const PolynomialVector<Trait, Domain::NTT>& vec) {
   PolynomialVector<Trait, Domain::NTT> result(mat.size());
   for(size_t i = 0; i < mat.size(); ++i) {
      Trait::polyvec_pointwise_acc_montgomery(result[i].coefficients(), mat[i].coefficients(), vec.coefficients());
   }
   return result;
}

template <crystals_trait Trait>
Polynomial<Trait, Domain::NTT> operator*(const PolynomialVector<Trait, Domain::NTT>& a,
                                         const PolynomialVector<Trait, Domain::NTT>& b) {
   Polynomial<Trait, Domain::NTT> result;
   detail::dot_product(result, a, b);
   return result;
}

template <crystals_trait Trait>
PolynomialVector<Trait, Domain::NTT> operator*(const Polynomial<Trait, Domain::NTT>& p,
                                               const PolynomialVector<Trait, Domain::NTT>& pv) {
   PolynomialVector<Trait, Domain::NTT> result(pv.size());
   for(size_t i = 0; i < pv.size(); ++i) {
      Trait::poly_pointwise_montgomery(result[i].coefficients(), p.coefficients(), pv[i].coefficients());
   }
   return result;
}

template <crystals_trait Trait>
Polynomial<Trait, Domain::NTT> operator*(const Polynomial<Trait, Domain::NTT>& a,
                                         const Polynomial<Trait, Domain::NTT>& b) {
   Polynomial<Trait, Domain::NTT> result;
   Trait::poly_pointwise_montgomery(result.coefficients(), a.coefficients(), b.coefficients());
   return result;
}

template <crystals_trait Trait>
PolynomialVector<Trait, Domain::Normal> operator<<(const PolynomialVector<Trait, Domain::Normal>& pv, size_t shift) {
   BOTAN_ASSERT_NOMSG(shift < sizeof(typename Trait::T) * 8);
   PolynomialVector<Trait, Domain::Normal> result(pv.size());
   for(size_t i = 0; i < pv.size(); ++i) {
      for(size_t j = 0; j < Trait::N; ++j) {
         result[i][j] = pv[i][j] << shift;
      }
   }
   return result;
}

}  // namespace Botan::CRYSTALS

#endif
