/*
 * Crystals Kyber Structures
 * Based on the public domain reference implementation by the
 * designers (https://github.com/pq-crystals/kyber)
 *
 * Further changes
 * (C) 2021-2024 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_KYBER_STRUCTURES_H_
#define BOTAN_KYBER_STRUCTURES_H_

#include <botan/exceptn.h>
#include <botan/xof.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/kyber_constants.h>
#include <botan/internal/kyber_symmetric_primitives.h>
#include <botan/internal/kyber_types.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

#include <span>

namespace Botan {

namespace detail {

/**
 * Constant time implementation for computing an unsigned integer division
 * with KyberConstants::Q = 3329.
 *
 * It enforces the optimization of various compilers,
 * replacing the division operation with multiplication and shifts.
 *
 * This implementation is only valid for integers <= 2**20
 *
 * @returns (a / KyberConstants::Q)
 */
inline constexpr uint16_t ct_int_div_kyber_q(uint32_t a) {
   BOTAN_DEBUG_ASSERT(a < (1 << 18));

   /*
   Constants based on "Hacker's Delight" (Second Edition) by Henry
   S. Warren, Jr. Chapter 10-9 "Unsigned Division by Divisors >= 1"
   */
   const uint64_t m = 161271;
   const size_t p = 29;
   return static_cast<uint16_t>((a * m) >> p);
}

}  // namespace detail

class Polynomial {
   public:
      Polynomial() : m_coeffs({0}) {}

      /**
       * Applies conditional subtraction of q to each coefficient of the polynomial.
       */
      void csubq() {
         for(auto& coeff : m_coeffs) {
            coeff -= KyberConstants::Q;
            coeff += (coeff >> 15) & KyberConstants::Q;
         }
      }

      /**
       * Applies Barrett reduction to all coefficients of the polynomial
       */
      void reduce() {
         for(auto& c : m_coeffs) {
            c = barrett_reduce(c);
         }
      }

      void to_bytes(std::span<uint8_t> out) {
         this->csubq();

         BufferStuffer bs(out);
         for(size_t i = 0; i < size() / 2; ++i) {
            const uint16_t t0 = m_coeffs[2 * i];
            const uint16_t t1 = m_coeffs[2 * i + 1];
            auto buf = bs.next<3>();
            buf[0] = static_cast<uint8_t>(t0 >> 0);
            buf[1] = static_cast<uint8_t>((t0 >> 8) | (t1 << 4));
            buf[2] = static_cast<uint8_t>(t1 >> 4);
         }
         BOTAN_ASSERT_NOMSG(bs.full());
      }

      /**
       * Given an array of uniformly random bytes, compute polynomial with coefficients
       * distributed according to a centered binomial distribution with parameter eta=2
       */
      static Polynomial cbd2(StrongSpan<const KyberSamplingRandomness> buf) {
         Polynomial r;

         BOTAN_ASSERT(buf.size() == (2 * r.size() / 4), "wrong input buffer size for cbd2");

         BufferSlicer bs(buf);
         for(size_t i = 0; i < r.size() / 8; ++i) {
            uint32_t t = load_le(bs.take<4>());
            uint32_t d = t & 0x55555555;
            d += (t >> 1) & 0x55555555;

            for(size_t j = 0; j < 8; ++j) {
               int16_t a = (d >> (4 * j + 0)) & 0x3;
               int16_t b = (d >> (4 * j + 2)) & 0x3;
               r.m_coeffs[8 * i + j] = a - b;
            }
         }
         BOTAN_ASSERT_NOMSG(bs.empty());

         return r;
      }

      /**
       * Given an array of uniformly random bytes, compute polynomial with coefficients
       * distributed according to a centered binomial distribution with parameter eta=3
       *
       * This function is only needed for Kyber-512
       */
      static Polynomial cbd3(StrongSpan<const KyberSamplingRandomness> buf) {
         Polynomial r;

         BOTAN_ASSERT(buf.size() == (3 * r.size() / 4), "wrong input buffer size for cbd3");

         // Note: load_le<> does not support loading a 3-byte value
         const auto load_le = [](std::span<const uint8_t, 3> in) { return make_uint32(0, in[2], in[1], in[0]); };

         BufferSlicer bs(buf);
         for(size_t i = 0; i < r.size() / 4; ++i) {
            uint32_t t = load_le(bs.take<3>());
            uint32_t d = t & 0x00249249;
            d += (t >> 1) & 0x00249249;
            d += (t >> 2) & 0x00249249;

            for(size_t j = 0; j < 4; ++j) {
               int16_t a = (d >> (6 * j + 0)) & 0x7;
               int16_t b = (d >> (6 * j + 3)) & 0x7;
               r.m_coeffs[4 * i + j] = a - b;
            }
         }
         BOTAN_ASSERT_NOMSG(bs.empty());

         return r;
      }

      /**
       * Sample a polynomial deterministically from a seed and a nonce, with output
       * polynomial close to centered binomial distribution with parameter eta=2.
       */
      static Polynomial getnoise_eta2(StrongSpan<const KyberEncryptionRandomness> seed,
                                      uint8_t nonce,
                                      const KyberConstants& mode) {
         const auto eta2 = mode.eta2();
         BOTAN_ASSERT(eta2 == 2, "Invalid eta2 value");

         const auto outlen = eta2 * KyberConstants::N / 4;
         return Polynomial::cbd2(mode.symmetric_primitives().PRF(seed, nonce, outlen));
      }

      /**
       * Sample a polynomial deterministically from a seed and a nonce, with output
       * polynomial close to centered binomial distribution with parameter mode.eta1()
       */
      static Polynomial getnoise_eta1(KyberSigmaOrEncryptionRandomness seed,
                                      uint8_t nonce,
                                      const KyberConstants& mode) {
         const auto eta1 = mode.eta1();
         BOTAN_ASSERT(eta1 == 2 || eta1 == 3, "Invalid eta1 value");

         const auto outlen = eta1 * KyberConstants::N / 4;
         return (eta1 == 2) ? Polynomial::cbd2(mode.symmetric_primitives().PRF(seed, nonce, outlen))
                            : Polynomial::cbd3(mode.symmetric_primitives().PRF(seed, nonce, outlen));
      }

      static Polynomial from_bytes(std::span<const uint8_t> a) {
         Polynomial r;
         for(size_t i = 0; i < r.size() / 2; ++i) {
            r.m_coeffs[2 * i] = ((a[3 * i + 0] >> 0) | (static_cast<uint16_t>(a[3 * i + 1]) << 8)) & 0xFFF;
            r.m_coeffs[2 * i + 1] = ((a[3 * i + 1] >> 4) | (static_cast<uint16_t>(a[3 * i + 2]) << 4)) & 0xFFF;
         }
         return r;
      }

      static Polynomial from_message(StrongSpan<const KyberMessage> msg) {
         BOTAN_ASSERT(msg.size() == KyberConstants::N / 8, "message length must be Kyber_N/8 bytes");

         Polynomial r;
         for(size_t i = 0; i < r.size() / 8; ++i) {
            for(size_t j = 0; j < 8; ++j) {
               const auto mask = CT::Mask<uint16_t>::is_zero((msg[i] >> j) & 1);
               r.m_coeffs[8 * i + j] = mask.if_not_set_return((KyberConstants::Q + 1) / 2);
            }
         }
         return r;
      }

      KyberMessage to_message() {
         KyberMessage result(size() / 8);

         this->csubq();

         for(size_t i = 0; i < size() / 8; ++i) {
            result[i] = 0;
            for(size_t j = 0; j < 8; ++j) {
               const uint16_t t = detail::ct_int_div_kyber_q((static_cast<uint16_t>(this->m_coeffs[8 * i + j]) << 1) +
                                                             KyberConstants::Q / 2);
               result[i] |= (t & 1) << j;
            }
         }

         return result;
      }

      /**
       * Adds two polynomials element-wise. Does not perform a reduction after the addition.
       * Therefore this operation might cause an integer overflow.
       */
      Polynomial& operator+=(const Polynomial& other) {
         for(size_t i = 0; i < this->size(); ++i) {
            BOTAN_DEBUG_ASSERT(static_cast<int32_t>(this->m_coeffs[i]) + other.m_coeffs[i] <=
                               std::numeric_limits<int16_t>::max());
            this->m_coeffs[i] = this->m_coeffs[i] + other.m_coeffs[i];
         }
         return *this;
      }

      /**
       * Subtracts two polynomials element-wise. Does not perform a reduction after the subtraction.
       * Therefore this operation might cause an integer underflow.
       */
      Polynomial& operator-=(const Polynomial& other) {
         for(size_t i = 0; i < this->size(); ++i) {
            BOTAN_DEBUG_ASSERT(static_cast<int32_t>(other.m_coeffs[i]) - this->m_coeffs[i] >=
                               std::numeric_limits<int16_t>::min());
            this->m_coeffs[i] = other.m_coeffs[i] - this->m_coeffs[i];
         }
         return *this;
      }

      /**
       * Multiplication of two polynomials in NTT domain
       */
      static Polynomial basemul_montgomery(const Polynomial& a, const Polynomial& b) {
         /**
          * Multiplication of polynomials in Zq[X]/(X^2-zeta) used for
          * multiplication of elements in Rq in NTT domain.
          */
         auto basemul = [](int16_t r[2], const int16_t s[2], const int16_t t[2], const int16_t zeta) {
            r[0] = fqmul(s[1], t[1]);
            r[0] = fqmul(r[0], zeta);
            r[0] += fqmul(s[0], t[0]);

            r[1] = fqmul(s[0], t[1]);
            r[1] += fqmul(s[1], t[0]);
         };

         Polynomial r;

         for(size_t i = 0; i < r.size() / 4; ++i) {
            basemul(&r.m_coeffs[4 * i], &a.m_coeffs[4 * i], &b.m_coeffs[4 * i], KyberConstants::zetas[64 + i]);
            basemul(
               &r.m_coeffs[4 * i + 2], &a.m_coeffs[4 * i + 2], &b.m_coeffs[4 * i + 2], -KyberConstants::zetas[64 + i]);
         }

         return r;
      }

      /**
       * Run rejection sampling on uniform random bytes to generate uniform
       * random integers mod q.
       */
      static Polynomial sample_rej_uniform(std::unique_ptr<XOF> xof) {
         Polynomial p;

         size_t count = 0;
         while(count < p.size()) {
            std::array<uint8_t, 3> buf;
            xof->output(buf);

            const uint16_t val0 = ((buf[0] >> 0) | (static_cast<uint16_t>(buf[1]) << 8)) & 0xFFF;
            const uint16_t val1 = ((buf[1] >> 4) | (static_cast<uint16_t>(buf[2]) << 4)) & 0xFFF;

            if(val0 < KyberConstants::Q) {
               p.m_coeffs[count++] = val0;
            }
            if(count < p.size() && val1 < KyberConstants::Q) {
               p.m_coeffs[count++] = val1;
            }
         }

         return p;
      }

      /**
       * Inplace conversion of all coefficients of a polynomial from normal
       * domain to Montgomery domain.
       */
      void tomont() {
         constexpr int16_t f = (1ULL << 32) % KyberConstants::Q;
         for(auto& c : m_coeffs) {
            c = montgomery_reduce(static_cast<int32_t>(c) * f);
         }
      }

      /**
       * Computes negacyclic number-theoretic transform (NTT) of a polynomial in place;
       * inputs assumed to be in normal order, output in bitreversed order.
       */
      void ntt() {
         for(size_t len = size() / 2, k = 0; len >= 2; len /= 2) {
            for(size_t start = 0, j = 0; start < size(); start = j + len) {
               const auto zeta = KyberConstants::zetas[++k];
               for(j = start; j < start + len; ++j) {
                  const auto t = fqmul(zeta, m_coeffs[j + len]);
                  m_coeffs[j + len] = m_coeffs[j] - t;
                  m_coeffs[j] = m_coeffs[j] + t;
               }
            }
         }

         reduce();
      }

      /**
       * Computes inverse of negacyclic number-theoretic transform (NTT) of a polynomial
       * in place; inputs assumed to be in bitreversed order, output in normal order.
       */
      void invntt_tomont() {
         for(size_t len = 2, k = 0; len <= size() / 2; len *= 2) {
            for(size_t start = 0, j = 0; start < size(); start = j + len) {
               const auto zeta = KyberConstants::zetas_inv[k++];
               for(j = start; j < start + len; ++j) {
                  const auto t = m_coeffs[j];
                  m_coeffs[j] = barrett_reduce(t + m_coeffs[j + len]);
                  m_coeffs[j + len] = fqmul(zeta, t - m_coeffs[j + len]);
               }
            }
         }

         for(auto& c : m_coeffs) {
            c = fqmul(c, KyberConstants::zetas_inv[127]);
         }
      }

      size_t size() const { return m_coeffs.size(); }

      int16_t operator[](size_t idx) const { return m_coeffs[idx]; }

      int16_t& operator[](size_t idx) { return m_coeffs[idx]; }

   private:
      /**
       * Barrett reduction; given a 16-bit integer a, computes 16-bit integer congruent
       * to a mod q in {0,...,q}.
       */
      static int16_t barrett_reduce(int16_t a) {
         constexpr int32_t v = ((1U << 26) + KyberConstants::Q / 2) / KyberConstants::Q;
         const int16_t t = (v * a >> 26) * KyberConstants::Q;
         return a - t;
      }

      /**
       * Multiplication followed by Montgomery reduction.
       */
      static int16_t fqmul(int16_t a, int16_t b) { return montgomery_reduce(static_cast<int32_t>(a) * b); }

      /**
       * Montgomery reduction; given a 32-bit integer a, computes 16-bit integer
       * congruent to a * R^-1 mod q, where R=2^16
       */
      static int16_t montgomery_reduce(int32_t a) {
         const int16_t u = static_cast<int16_t>(a * KyberConstants::Q_Inv);
         int32_t t = static_cast<int32_t>(u) * KyberConstants::Q;
         t = a - t;
         t >>= 16;
         return static_cast<int16_t>(t);
      }

      std::array<int16_t, KyberConstants::N> m_coeffs;
};

class PolynomialVector {
   public:
      PolynomialVector() = delete;

      explicit PolynomialVector(const size_t k) : m_vec(k) {}

   public:
      static PolynomialVector from_bytes(std::span<const uint8_t> a, const KyberConstants& mode) {
         BOTAN_ASSERT(a.size() == mode.polynomial_vector_byte_length(), "wrong byte length for frombytes");

         PolynomialVector r(mode.k());

         BufferSlicer bs(a);
         for(size_t i = 0; i < mode.k(); ++i) {
            r.m_vec[i] = Polynomial::from_bytes(bs.take(KyberConstants::kSerializedPolynomialByteLength));
         }
         BOTAN_ASSERT_NOMSG(bs.empty());

         return r;
      }

      /**
       * Pointwise multiply elements of a and b, accumulate into r, and multiply by 2^-16.
       */
      static Polynomial pointwise_acc_montgomery(const PolynomialVector& a, const PolynomialVector& b) {
         BOTAN_ASSERT(a.m_vec.size() == b.m_vec.size(),
                      "pointwise_acc_montgomery works on equally sized "
                      "PolynomialVectors only");

         Polynomial r;
         for(size_t i = 0; i < a.m_vec.size(); ++i) {
            r += Polynomial::basemul_montgomery(a.m_vec[i], b.m_vec[i]);
         }
         r.reduce();
         return r;
      }

      static PolynomialVector getnoise_eta2(StrongSpan<const KyberEncryptionRandomness> seed,
                                            uint8_t nonce,
                                            const KyberConstants& mode) {
         PolynomialVector r(mode.k());
         for(auto& p : r.m_vec) {
            p = Polynomial::getnoise_eta2(seed, nonce++, mode);
         }
         return r;
      }

      static PolynomialVector getnoise_eta1(KyberSigmaOrEncryptionRandomness seed,
                                            uint8_t nonce,
                                            const KyberConstants& mode) {
         PolynomialVector r(mode.k());
         for(auto& p : r.m_vec) {
            p = Polynomial::getnoise_eta1(seed, nonce++, mode);
         }
         return r;
      }

      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
      T to_bytes() {
         T r(m_vec.size() * KyberConstants::kSerializedPolynomialByteLength);

         BufferStuffer bs(r);
         for(auto& v : m_vec) {
            v.to_bytes(bs.next(KyberConstants::kSerializedPolynomialByteLength));
         }
         BOTAN_ASSERT_NOMSG(bs.full());

         return r;
      }

      /**
       * Applies conditional subtraction of q to each coefficient of each element
       * of the vector of polynomials.
       */
      void csubq() {
         for(auto& p : m_vec) {
            p.csubq();
         }
      }

      PolynomialVector& operator+=(const PolynomialVector& other) {
         BOTAN_ASSERT(m_vec.size() == other.m_vec.size(), "cannot add polynomial vectors of differing lengths");

         for(size_t i = 0; i < m_vec.size(); ++i) {
            m_vec[i] += other.m_vec[i];
         }
         return *this;
      }

      Polynomial& operator[](size_t idx) { return m_vec[idx]; }

      /**
       * Applies Barrett reduction to each coefficient of each element of a vector of polynomials.
       */
      void reduce() {
         for(auto& v : m_vec) {
            v.reduce();
         }
      }

      /**
       * Apply inverse NTT to all elements of a vector of polynomials and multiply by Montgomery factor 2^16.
       */
      void invntt_tomont() {
         for(auto& v : m_vec) {
            v.invntt_tomont();
         }
      }

      /**
       * Apply forward NTT to all elements of a vector of polynomials.
       */
      void ntt() {
         for(auto& v : m_vec) {
            v.ntt();
         }
      }

   private:
      std::vector<Polynomial> m_vec;
};

class PolynomialMatrix {
   public:
      PolynomialMatrix() = delete;

      static PolynomialMatrix generate(StrongSpan<const KyberSeedRho> seed,
                                       const bool transposed,
                                       const KyberConstants& mode) {
         BOTAN_ASSERT(seed.size() == KyberConstants::kSymBytes, "unexpected seed size");

         PolynomialMatrix matrix(mode);

         for(uint8_t i = 0; i < mode.k(); ++i) {
            for(uint8_t j = 0; j < mode.k(); ++j) {
               const auto pos = (transposed) ? std::tuple(i, j) : std::tuple(j, i);
               matrix.m_mat[i][j] = Polynomial::sample_rej_uniform(mode.symmetric_primitives().XOF(seed, pos));
            }
         }

         return matrix;
      }

      PolynomialVector pointwise_acc_montgomery(const PolynomialVector& vec, const bool with_mont = false) const {
         PolynomialVector result(m_mat.size());

         for(size_t i = 0; i < m_mat.size(); ++i) {
            result[i] = PolynomialVector::pointwise_acc_montgomery(m_mat[i], vec);
            if(with_mont) {
               result[i].tomont();
            }
         }

         return result;
      }

   private:
      explicit PolynomialMatrix(const KyberConstants& mode) : m_mat(mode.k(), PolynomialVector(mode.k())) {}

   private:
      std::vector<PolynomialVector> m_mat;
};

class Ciphertext {
   public:
      Ciphertext() = delete;

      Ciphertext(PolynomialVector b, const Polynomial& v, KyberConstants mode) :
            m_mode(std::move(mode)), m_b(std::move(b)), m_v(v) {}

      static Ciphertext from_bytes(StrongSpan<const KyberCompressedCiphertext> buffer, const KyberConstants& mode) {
         const size_t pvb = mode.polynomial_vector_compressed_bytes();
         const size_t pcb = mode.polynomial_compressed_bytes();

         if(buffer.size() != pvb + pcb) {
            throw Decoding_Error("Kyber: unexpected ciphertext length");
         }

         BufferSlicer bs(buffer);
         auto pv = bs.take(pvb);
         auto p = bs.take(pcb);
         BOTAN_ASSERT_NOMSG(bs.empty());

         return Ciphertext(decompress_polynomial_vector(pv, mode), decompress_polynomial(p, mode), mode);
      }

      void to_bytes(StrongSpan<KyberCompressedCiphertext> out) {
         BufferStuffer bs(out);
         compress(bs.next(m_mode.polynomial_vector_compressed_bytes()), m_b, m_mode);
         compress(bs.next(m_mode.polynomial_compressed_bytes()), m_v, m_mode);
         BOTAN_ASSERT_NOMSG(bs.full());
      }

      KyberCompressedCiphertext to_bytes() {
         KyberCompressedCiphertext r(m_mode.encapsulated_key_length());
         to_bytes(r);
         return r;
      }

      PolynomialVector& b() { return m_b; }

      Polynomial& v() { return m_v; }

   private:
      static void compress(std::span<uint8_t> out, PolynomialVector& pv, const KyberConstants& mode) {
         pv.csubq();

         BufferStuffer bs(out);
         if(mode.k() == 2 || mode.k() == 3) {
            uint16_t t[4];
            for(size_t i = 0; i < mode.k(); ++i) {
               for(size_t j = 0; j < KyberConstants::N / 4; ++j) {
                  for(size_t k = 0; k < 4; ++k) {
                     t[k] = (((static_cast<uint32_t>(pv[i][4 * j + k]) << 10) + KyberConstants::Q / 2) /
                             KyberConstants::Q) &
                            0x3ff;
                  }

                  auto r = bs.next<5>();
                  r[0] = static_cast<uint8_t>(t[0] >> 0);
                  r[1] = static_cast<uint8_t>((t[0] >> 8) | (t[1] << 2));
                  r[2] = static_cast<uint8_t>((t[1] >> 6) | (t[2] << 4));
                  r[3] = static_cast<uint8_t>((t[2] >> 4) | (t[3] << 6));
                  r[4] = static_cast<uint8_t>(t[3] >> 2);
               }
            }
         } else {
            uint16_t t[8];
            for(size_t i = 0; i < mode.k(); ++i) {
               for(size_t j = 0; j < KyberConstants::N / 8; ++j) {
                  for(size_t k = 0; k < 8; ++k) {
                     t[k] = (((static_cast<uint32_t>(pv[i][8 * j + k]) << 11) + KyberConstants::Q / 2) /
                             KyberConstants::Q) &
                            0x7ff;
                  }

                  auto r = bs.next<11>();
                  r[0] = static_cast<uint8_t>(t[0] >> 0);
                  r[1] = static_cast<uint8_t>((t[0] >> 8) | (t[1] << 3));
                  r[2] = static_cast<uint8_t>((t[1] >> 5) | (t[2] << 6));
                  r[3] = static_cast<uint8_t>(t[2] >> 2);
                  r[4] = static_cast<uint8_t>((t[2] >> 10) | (t[3] << 1));
                  r[5] = static_cast<uint8_t>((t[3] >> 7) | (t[4] << 4));
                  r[6] = static_cast<uint8_t>((t[4] >> 4) | (t[5] << 7));
                  r[7] = static_cast<uint8_t>(t[5] >> 1);
                  r[8] = static_cast<uint8_t>((t[5] >> 9) | (t[6] << 2));
                  r[9] = static_cast<uint8_t>((t[6] >> 6) | (t[7] << 5));
                  r[10] = static_cast<uint8_t>(t[7] >> 3);
               }
            }
         }

         BOTAN_ASSERT_NOMSG(bs.full());
      }

      static void compress(std::span<uint8_t> out, Polynomial& p, const KyberConstants& mode) {
         p.csubq();

         BufferStuffer bs(out);
         uint8_t t[8];
         if(mode.k() == 2 || mode.k() == 3) {
            for(size_t i = 0; i < p.size() / 8; ++i) {
               for(size_t j = 0; j < 8; ++j) {
                  t[j] =
                     detail::ct_int_div_kyber_q((static_cast<uint16_t>(p[8 * i + j]) << 4) + KyberConstants::Q / 2) &
                     15;
               }

               auto r = bs.next<4>();
               r[0] = t[0] | (t[1] << 4);
               r[1] = t[2] | (t[3] << 4);
               r[2] = t[4] | (t[5] << 4);
               r[3] = t[6] | (t[7] << 4);
            }
         } else if(mode.k() == 4) {
            for(size_t i = 0; i < p.size() / 8; ++i) {
               for(size_t j = 0; j < 8; ++j) {
                  t[j] =
                     detail::ct_int_div_kyber_q((static_cast<uint32_t>(p[8 * i + j]) << 5) + KyberConstants::Q / 2) &
                     31;
               }

               auto r = bs.next<5>();
               r[0] = (t[0] >> 0) | (t[1] << 5);
               r[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
               r[2] = (t[3] >> 1) | (t[4] << 4);
               r[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
               r[4] = (t[6] >> 2) | (t[7] << 3);
            }
         }

         BOTAN_ASSERT_NOMSG(bs.full());
      }

      static PolynomialVector decompress_polynomial_vector(std::span<const uint8_t> buffer,
                                                           const KyberConstants& mode) {
         BOTAN_ASSERT(buffer.size() == mode.polynomial_vector_compressed_bytes(),
                      "unexpected length of compressed polynomial vector");

         PolynomialVector r(mode.k());
         BufferSlicer bs(buffer);
         if(mode.k() == 4) {
            uint16_t t[8];
            for(size_t i = 0; i < mode.k(); ++i) {
               for(size_t j = 0; j < KyberConstants::N / 8; ++j) {
                  const auto a = bs.take<11>();
                  t[0] = (a[0] >> 0) | (static_cast<uint16_t>(a[1]) << 8);
                  t[1] = (a[1] >> 3) | (static_cast<uint16_t>(a[2]) << 5);
                  t[2] = (a[2] >> 6) | (static_cast<uint16_t>(a[3]) << 2) | (static_cast<uint16_t>(a[4]) << 10);
                  t[3] = (a[4] >> 1) | (static_cast<uint16_t>(a[5]) << 7);
                  t[4] = (a[5] >> 4) | (static_cast<uint16_t>(a[6]) << 4);
                  t[5] = (a[6] >> 7) | (static_cast<uint16_t>(a[7]) << 1) | (static_cast<uint16_t>(a[8]) << 9);
                  t[6] = (a[8] >> 2) | (static_cast<uint16_t>(a[9]) << 6);
                  t[7] = (a[9] >> 5) | (static_cast<uint16_t>(a[10]) << 3);

                  for(size_t k = 0; k < 8; ++k) {
                     r[i][8 * j + k] = (static_cast<uint32_t>(t[k] & 0x7FF) * KyberConstants::Q + 1024) >> 11;
                  }
               }
            }
         } else {
            uint16_t t[4];
            for(size_t i = 0; i < mode.k(); ++i) {
               for(size_t j = 0; j < KyberConstants::N / 4; ++j) {
                  const auto a = bs.take<5>();
                  t[0] = (a[0] >> 0) | (static_cast<uint16_t>(a[1]) << 8);
                  t[1] = (a[1] >> 2) | (static_cast<uint16_t>(a[2]) << 6);
                  t[2] = (a[2] >> 4) | (static_cast<uint16_t>(a[3]) << 4);
                  t[3] = (a[3] >> 6) | (static_cast<uint16_t>(a[4]) << 2);

                  for(size_t k = 0; k < 4; ++k) {
                     r[i][4 * j + k] = (static_cast<uint32_t>(t[k] & 0x3FF) * KyberConstants::Q + 512) >> 10;
                  }
               }
            }
         }
         BOTAN_ASSERT_NOMSG(bs.empty());

         return r;
      }

      static Polynomial decompress_polynomial(std::span<const uint8_t> buffer, const KyberConstants& mode) {
         BOTAN_ASSERT(buffer.size() == mode.polynomial_compressed_bytes(),
                      "unexpected length of compressed polynomial");

         Polynomial r;
         BufferSlicer bs(buffer);
         if(mode.k() == 4) {
            uint8_t t[8];
            for(size_t i = 0; i < KyberConstants::N / 8; ++i) {
               const auto a = bs.take<5>();
               t[0] = (a[0] >> 0);
               t[1] = (a[0] >> 5) | (a[1] << 3);
               t[2] = (a[1] >> 2);
               t[3] = (a[1] >> 7) | (a[2] << 1);
               t[4] = (a[2] >> 4) | (a[3] << 4);
               t[5] = (a[3] >> 1);
               t[6] = (a[3] >> 6) | (a[4] << 2);
               t[7] = (a[4] >> 3);

               for(size_t j = 0; j < 8; ++j) {
                  r[8 * i + j] = (static_cast<uint32_t>(t[j] & 31) * KyberConstants::Q + 16) >> 5;
               }
            }
         } else {
            for(size_t i = 0; i < KyberConstants::N / 2; ++i) {
               const auto a = bs.take_byte();
               r[2 * i + 0] = ((static_cast<uint16_t>(a & 15) * KyberConstants::Q) + 8) >> 4;
               r[2 * i + 1] = ((static_cast<uint16_t>(a >> 4) * KyberConstants::Q) + 8) >> 4;
            }
         }
         BOTAN_ASSERT_NOMSG(bs.empty());

         return r;
      }

   private:
      KyberConstants m_mode;
      PolynomialVector m_b;
      Polynomial m_v;
};

}  // namespace Botan

#endif
