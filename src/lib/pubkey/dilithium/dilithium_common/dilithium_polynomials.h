/*
* Crystals Dilithium Digital Signature Algorithms
* Based on the public domain reference implementation by the
* designers (https://github.com/pq-crystals/dilithium)
*
* Further changes
* (C) 2021-2023 Jack Lloyd
* (C) 2021-2022 Manuel Glaser - Rohde & Schwarz Cybersecurity
* (C) 2021-2023 Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DILITHIUM_POLYNOMIAL_H_
#define BOTAN_DILITHIUM_POLYNOMIAL_H_

#include <botan/dilithium.h>

#include <botan/internal/dilithium_symmetric_primitives.h>
#include <botan/internal/shake.h>

#include <array>
#include <span>
#include <vector>

namespace Botan::Dilithium {

class Polynomial {
   public:
      // public member is on purpose
      std::array<int32_t, Botan::DilithiumModeConstants::N> m_coeffs;

      /**
      * Adds two polynomials element-wise. Does not perform a reduction after the addition.
      * Therefore this operation might cause an integer overflow.
      */
      Polynomial& operator+=(const Polynomial& other) {
         for(size_t i = 0; i < this->m_coeffs.size(); ++i) {
            this->m_coeffs[i] = this->m_coeffs[i] + other.m_coeffs[i];
         }
         return *this;
      }

      /**
      * Subtracts two polynomials element-wise. Does not perform a reduction after the subtraction.
      * Therefore this operation might cause an integer underflow.
      */
      Polynomial& operator-=(const Polynomial& other) {
         for(size_t i = 0; i < this->m_coeffs.size(); ++i) {
            this->m_coeffs[i] = this->m_coeffs[i] - other.m_coeffs[i];
         }
         return *this;
      }

      /***************************************************
      * Name:        rej_uniform
      *
      * Description: Sample uniformly random coefficients in [0, Q-1] by
      *              performing rejection sampling on array of random bytes.
      *
      * Arguments:   - Polynomial& a: reference to output array (allocated)
      *              - size_t position: starting point
      *              - size_t len: number of coefficients to be sampled
      *              - const uint8_t *buf: array of random bytes
      *              - size_t buflen: length of array of random bytes
      *
      * Returns number of sampled coefficients. Can be smaller than len if not enough
      * random bytes were given.
      **************************************************/
      static size_t rej_uniform(Polynomial& p, size_t position, size_t len, const uint8_t* buf, size_t buflen) {
         size_t ctr = 0, pos = 0;
         while(ctr < len && pos + 3 <= buflen) {
            uint32_t t = buf[pos++];
            t |= static_cast<uint32_t>(buf[pos++]) << 8;
            t |= static_cast<uint32_t>(buf[pos++]) << 16;
            t &= 0x7FFFFF;

            if(t < DilithiumModeConstants::Q) {
               p.m_coeffs[position + ctr++] = static_cast<int32_t>(t);
            }
         }
         return ctr;
      }

      /*************************************************
      * Name:        rej_eta
      *
      * Description: Sample uniformly random coefficients in [-ETA, ETA] by
      *              performing rejection sampling on array of random bytes.
      *
      * Arguments:   - Polynomial &a: pointer to output array (allocated)
      *              - size_t offset: starting point for the output polynomial
      *              - size_t len: number of coefficients to be sampled
      *              - const secure_vector<uint8_t>& buf: sv reference of random bytes
      *              - size_t buflen: length of array of random bytes
      *              - const DilithiumModeConstants&
      *
      * Returns number of sampled coefficients. Can be smaller than len if not enough
      * random bytes were given.
      **************************************************/
      static size_t rej_eta(Polynomial& a,
                            size_t offset,
                            size_t len,
                            const secure_vector<uint8_t>& buf,
                            size_t buflen,
                            const DilithiumModeConstants& mode) {
         size_t ctr = 0, pos = 0;
         while(ctr < len && pos < buflen) {
            uint32_t t0 = buf[pos] & 0x0F;
            uint32_t t1 = buf[pos++] >> 4;

            switch(mode.eta()) {
               case DilithiumEta::Eta2: {
                  if(t0 < 15) {
                     t0 = t0 - (205 * t0 >> 10) * 5;
                     a.m_coeffs[offset + ctr++] = 2 - t0;
                  }
                  if(t1 < 15 && ctr < len) {
                     t1 = t1 - (205 * t1 >> 10) * 5;
                     a.m_coeffs[offset + ctr++] = 2 - t1;
                  }
               } break;
               case DilithiumEta::Eta4: {
                  if(t0 < 9) {
                     a.m_coeffs[offset + ctr++] = 4 - t0;
                  }
                  if(t1 < 9 && ctr < len) {
                     a.m_coeffs[offset + ctr++] = 4 - t1;
                  }
               } break;
            }
         }
         return ctr;
      }

      /*************************************************
      * Name:        fill_poly_uniform_eta
      *
      * Description: Sample polynomial with uniformly random coefficients
      *              in [-ETA,ETA] by performing rejection sampling on the
      *              output stream from SHAKE256(seed|nonce) or AES256CTR(seed,nonce).
      *
      * Arguments:   - Polynomial& a: reference to output polynomial
      *              - const uint8_t seed[]: byte array with seed of length CRHBYTES
      *              - uint16_t nonce: 2-byte nonce
      *              - const DilithiumModeConstants& mode: Mode dependent values.
      **************************************************/
      static void fill_poly_uniform_eta(Polynomial& a,
                                        const secure_vector<uint8_t>& seed,
                                        uint16_t nonce,
                                        const DilithiumModeConstants& mode) {
         BOTAN_ASSERT_NOMSG(seed.size() == DilithiumModeConstants::CRHBYTES);

         auto xof = mode.XOF_256(seed, nonce);

         secure_vector<uint8_t> buf(mode.poly_uniform_eta_nblocks() * mode.stream256_blockbytes());
         xof->output(buf);
         size_t ctr = Polynomial::rej_eta(a, 0, DilithiumModeConstants::N, buf, buf.size(), mode);

         while(ctr < DilithiumModeConstants::N) {
            xof->output(std::span(buf).first(mode.stream256_blockbytes()));
            ctr += Polynomial::rej_eta(a, ctr, DilithiumModeConstants::N - ctr, buf, mode.stream256_blockbytes(), mode);
         }
      }

      /*************************************************
      * Name:        power2round
      *
      * Description: For finite field element a, compute a0, a1 such that
      *              a mod^+ Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
      *              Assumes a to be standard representative.
      *
      * Arguments:   - int32_t a: input element
      *              - int32_t *a0: pointer to output element a0
      *
      * Returns a1.
      **************************************************/
      static int32_t power2round(int32_t& a0, int32_t a) {
         int32_t a1 = (a + (1 << (DilithiumModeConstants::D - 1)) - 1) >> DilithiumModeConstants::D;
         a0 = a - (a1 << DilithiumModeConstants::D);
         return a1;
      }

      /*************************************************
      * Name:        fill_polys_power2round
      *
      * Description: For all coefficients c of the input polynomial,
      *              compute c0, c1 such that c mod Q = c1*2^D + c0
      *              with -2^{D-1} < c0 <= 2^{D-1}. Assumes coefficients to be
      *              standard representatives.
      *
      * Arguments:   - Polynomial& a1: pointer to output polynomial with coefficients c1
      *              - Polynomial& a0: pointer to output polynomial with coefficients c0
      *              - const Polynomial& a: pointer to input polynomial
      **************************************************/
      static void fill_polys_power2round(Polynomial& a1, Polynomial& a0, const Polynomial& a) {
         for(size_t i = 0; i < DilithiumModeConstants::N; ++i) {
            a1.m_coeffs[i] = Polynomial::power2round(a0.m_coeffs[i], a.m_coeffs[i]);
         }
      }

      /*************************************************
      * Name:        challenge
      *
      * Description: Implementation of H. Samples polynomial with TAU nonzero
      *              coefficients in {-1,1} using the output stream of
      *              SHAKE256(seed).
      *
      * Arguments:   - Polynomial &c: pointer to output polynomial
      *              - const uint8_t mu[]: byte array containing seed of length SEEDBYTES
      *           - const DilithiumModeConstants& mode: reference to dilihtium mode values
      **************************************************/
      static Polynomial poly_challenge(const uint8_t* seed, const DilithiumModeConstants& mode) {
         Polynomial c;

         SHAKE_256 shake256_hasher(DilithiumModeConstants::SHAKE256_RATE * 8);
         shake256_hasher.update(seed, DilithiumModeConstants::SEEDBYTES);
         auto buf = shake256_hasher.final();

         uint64_t signs = 0;
         for(size_t i = 0; i < 8; ++i) {
            signs |= static_cast<uint64_t>(buf[i]) << 8 * i;
         }
         size_t pos = 8;

         for(size_t i = 0; i < DilithiumModeConstants::N; ++i) {
            c.m_coeffs[i] = 0;
         }
         for(size_t i = DilithiumModeConstants::N - mode.tau(); i < DilithiumModeConstants::N; ++i) {
            size_t b;
            do {
               b = buf[pos++];
            } while(b > i);

            c.m_coeffs[i] = c.m_coeffs[b];
            c.m_coeffs[b] = 1 - 2 * (signs & 1);
            signs >>= 1;
         }
         return c;
      }

      /*************************************************
      * Name:        poly_chknorm
      *
      * Description: Check infinity norm of polynomial against given bound.
      *              Assumes input coefficients were reduced by reduce32().
      *
      * Arguments:   - const Polynomial& a: pointer to polynomial
      *              - size_t B: norm bound
      *
      * Returns false if norm is strictly smaller than B <= (Q-1)/8 and true otherwise.
      **************************************************/
      static bool poly_chknorm(const Polynomial& a, size_t B) {
         if(B > (DilithiumModeConstants::Q - 1) / 8) {
            return true;
         }

         /* It is ok to leak which coefficient violates the bound since
         the probability for each coefficient is independent of secret
         data but we must not leak the sign of the centralized representative. */
         for(const auto& coeff : a.m_coeffs) {
            /* Absolute value */
            size_t t = coeff >> 31;
            t = coeff - (t & 2 * coeff);

            if(t >= B) {
               return true;
            }
         }
         return false;
      }

      /*************************************************
      * Name:        make_hint
      *
      * Description: Compute hint bit indicating whether the low bits of the
      *              input element overflow into the high bits. Inputs assumed
      *              to be standard representatives.
      *
      * Arguments:   - size_t a0: low bits of input element
      *              - size_t a1: high bits of input element
      *              - const DilithiumModeConstants& mode: reference to dilihtium mode values
      *
      * Returns 1 if overflow.
      **************************************************/
      static int32_t make_hint(size_t a0, size_t a1, const DilithiumModeConstants& mode) {
         const auto gamma2 = mode.gamma2();
         const auto Q_gamma2 = DilithiumModeConstants::Q - gamma2;
         if(a0 <= gamma2 || a0 > Q_gamma2 || (a0 == Q_gamma2 && a1 == 0)) {
            return 0;
         }
         return 1;
      }

      /*************************************************
      * Name:        generate_hint_polynomial
      *
      * Description: Compute hint polynomial. The coefficients of which indicate
      *              whether the low bits of the corresponding coefficient of
      *              the input polynomial overflow into the high bits.
      *
      * Arguments:   - Polynomial& h: reference to output hint polynomial
      *              - const Polynomial& a0: reference to low part of input polynomial
      *              - const Polynomial& a1: reference to high part of input polynomial
      *           - const DilithiumModeConstants& mode: reference to dilihtium mode values
      *
      * Returns number of 1 bits.
      **************************************************/
      static size_t generate_hint_polynomial(Polynomial& h,
                                             const Polynomial& a0,
                                             const Polynomial& a1,
                                             const DilithiumModeConstants& mode) {
         size_t s = 0;

         for(size_t i = 0; i < DilithiumModeConstants::N; ++i) {
            h.m_coeffs[i] = Polynomial::make_hint(a0.m_coeffs[i], a1.m_coeffs[i], mode);
            s += h.m_coeffs[i];
         }

         return s;
      }

      /*************************************************
      * Name:        decompose
      *
      * Description: For finite field element a, compute high and low bits a0, a1 such
      *              that a mod^+ Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except
      *              if a1 = (Q-1)/ALPHA where we set a1 = 0 and
      *              -ALPHA/2 <= a0 = a mod^+ Q - Q < 0. Assumes a to be standard
      *              representative.
      *
      * Arguments:   - int32_t a: input element
      *              - int32_t *a0: pointer to output element a0
      *           - const DilithiumModeConstants& mode: reference to dilihtium mode values
      *
      * Returns a1.
      **************************************************/
      static int32_t decompose(int32_t* a0, int32_t a, const DilithiumModeConstants& mode) {
         int32_t a1 = (a + 127) >> 7;
         if(mode.gamma2() == (DilithiumModeConstants::Q - 1) / 32) {
            a1 = (a1 * 1025 + (1 << 21)) >> 22;
            a1 &= 15;
         } else {
            BOTAN_ASSERT_NOMSG(mode.gamma2() == (DilithiumModeConstants::Q - 1) / 88);
            a1 = (a1 * 11275 + (1 << 23)) >> 24;
            a1 ^= ((43 - a1) >> 31) & a1;
         }

         *a0 = a - a1 * 2 * static_cast<int32_t>(mode.gamma2());
         *a0 -= (((DilithiumModeConstants::Q - 1) / 2 - *a0) >> 31) & DilithiumModeConstants::Q;
         return a1;
      }

      /*************************************************
      * Name:        use_hint
      *
      * Description: Correct high bits according to hint.
      *
      * Arguments:   - int32_t a: input element
      *              - size_t hint: hint bit
      *           - const DilithiumModeConstants& mode: reference to dilihtium mode values
      *
      * Returns corrected high bits.
      **************************************************/
      static int32_t use_hint(int32_t a, size_t hint, const DilithiumModeConstants& mode) {
         int32_t a0;

         int32_t a1 = Polynomial::decompose(&a0, a, mode);
         if(hint == 0) {
            return a1;
         }

         if(mode.gamma2() == ((DilithiumModeConstants::Q - 1) / 32)) {
            if(a0 > 0) {
               return (a1 + 1) & 15;
            } else {
               return (a1 - 1) & 15;
            }
         } else {
            if(a0 > 0) {
               return (a1 == 43) ? 0 : a1 + 1;
            } else {
               return (a1 == 0) ? 43 : a1 - 1;
            }
         }
      }

      /*************************************************
      * Name:        poly_use_hint
      *
      * Description: Use hint polynomial to correct the high bits of a polynomial.
      *
      * Arguments:   - Polynomial& b: reference to output polynomial with corrected high bits
      *              - const Polynomial& a: reference to input polynomial
      *              - const Polynomial& h: reference to input hint polynomial
      *           - const DilithiumModeConstants& mode: reference to dilihtium mode values
      *
      **************************************************/
      static void poly_use_hint(Polynomial& b,
                                const Polynomial& a,
                                const Polynomial& h,
                                const DilithiumModeConstants& mode) {
         for(size_t i = 0; i < DilithiumModeConstants::N; ++i) {
            b.m_coeffs[i] = Polynomial::use_hint(a.m_coeffs[i], h.m_coeffs[i], mode);
         }
      }

      /*************************************************
      * Name:        montgomery_reduce
      *
      * Description: For finite field element a with -2^{31}Q <= a <= Q*2^31,
      *              compute r \equiv a*2^{-32} (mod Q) such that -Q < r < Q.
      *
      * Arguments:   - int64_t: finite field element a
      *
      * Returns r.
      **************************************************/
      int32_t montgomery_reduce(int64_t a) const {
         int32_t t = static_cast<int32_t>(static_cast<int64_t>(static_cast<int32_t>(a)) * DilithiumModeConstants::QINV);
         t = (a - static_cast<int64_t>(t) * DilithiumModeConstants::Q) >> 32;
         return t;
      }

      /*************************************************
      * Name:        poly_pointwise_montgomery
      *
      * Description: Pointwise multiplication of polynomials in NTT domain
      *              representation and multiplication of resulting polynomial
      *              by 2^{-32}.
      *           For finite field element a with -2^{31}Q <= a <= Q*2^31,
      *              compute r \equiv a*2^{-32} (mod Q) such that -Q < r < Q.
      *
      * Arguments:   - Polynomial& c: reference to output polynomial
      *              - const Polynomial& a: reference to first input polynomial
      *              - const Polynomial& b: reference  to second input polynomial
      **************************************************/
      void poly_pointwise_montgomery(Polynomial& output, const Polynomial& second) const {
         for(size_t i = 0; i < DilithiumModeConstants::N; ++i) {
            output.m_coeffs[i] = montgomery_reduce(static_cast<int64_t>(m_coeffs[i]) * second.m_coeffs[i]);
         }
      }

      /*************************************************
      * Name:        ntt
      *
      * Description: Forward NTT, in-place. No modular reduction is performed after
      *              additions or subtractions. Output vector is in bitreversed order.
      *
      * Arguments:   - Polynomial& a: input/output coefficient Polynomial
      **************************************************/
      void ntt() {
         size_t j;
         size_t k = 0;

         for(size_t len = 128; len > 0; len >>= 1) {
            for(size_t start = 0; start < DilithiumModeConstants::N; start = j + len) {
               int32_t zeta = DilithiumModeConstants::ZETAS[++k];
               for(j = start; j < start + len; ++j) {
                  int32_t t = montgomery_reduce(static_cast<int64_t>(zeta) * m_coeffs[j + len]);
                  m_coeffs[j + len] = m_coeffs[j] - t;
                  m_coeffs[j] = m_coeffs[j] + t;
               }
            }
         }
      }

      /*************************************************
      * Name:        poly_reduce
      *
      * Description: Inplace reduction of all coefficients of polynomial to
      *              representative in [-6283009,6283007].
      *           For finite field element a with a <= 2^{31} - 2^{22} - 1,
      *              compute r \equiv a (mod Q) such that -6283009 <= r <= 6283007.
      *
      * Arguments:   - Polynomial &a: reference to input polynomial
      **************************************************/
      void poly_reduce() {
         for(auto& i : m_coeffs) {
            int32_t t = (i + (1 << 22)) >> 23;
            t = i - t * DilithiumModeConstants::Q;
            i = t;
         }
      }

      /*************************************************
      * Name:        invntt_tomont
      *
      * Description: Inverse NTT and multiplication by Montgomery factor 2^32.
      *              In-place. No modular reductions after additions or
      *              subtractions; input coefficients need to be smaller than
      *              Q in absolute value. Output coefficient are smaller than Q in
      *              absolute value.
      **************************************************/
      void invntt_tomont() {
         size_t j;
         int32_t f = 41978;  // mont^2/256
         size_t k = 256;
         for(size_t len = 1; len < DilithiumModeConstants::N; len <<= 1) {
            for(size_t start = 0; start < DilithiumModeConstants::N; start = j + len) {
               int32_t zeta = -DilithiumModeConstants::ZETAS[--k];
               for(j = start; j < start + len; ++j) {
                  int32_t t = m_coeffs[j];
                  m_coeffs[j] = t + m_coeffs[j + len];
                  m_coeffs[j + len] = t - m_coeffs[j + len];
                  m_coeffs[j + len] = montgomery_reduce(static_cast<int64_t>(zeta) * m_coeffs[j + len]);
               }
            }
         }

         for(j = 0; j < DilithiumModeConstants::N; ++j) {
            m_coeffs[j] = montgomery_reduce(static_cast<int64_t>(f) * m_coeffs[j]);
         }
      }

      /*************************************************
      * Name:        poly_invntt_tomont
      *
      * Description: Inplace inverse NTT and multiplication by 2^{32}.
      *              Input coefficients need to be less than Q in absolute
      *              value and output coefficients are again bounded by Q.
      *
      * Arguments:   - Polynomial& a: reference to input/output polynomial
      **************************************************/
      void poly_invntt_tomont() { invntt_tomont(); }

      /*************************************************
      * Name:        cadd_q
      *
      * Description: For all coefficients of in/out polynomial add Q if
      *              coefficient is negative.
      *           Add Q if input coefficient is negative.
      **************************************************/
      void cadd_q() {
         for(auto& i : m_coeffs) {
            i += (i >> 31) & DilithiumModeConstants::Q;
         }
      }

      /*************************************************
      * Name:        poly_uniform_gamma1
      *
      * Description: Sample polynomial with uniformly random coefficients
      *              in [-(GAMMA1 - 1), GAMMA1] by unpacking output stream
      *              of SHAKE256(seed|nonce) or AES256CTR(seed,nonce).
      *
      * Arguments:   - const secure_vector<uint8_t>& seed: vector with seed of length CRHBYTES
      *              - uint16_t nonce: 16-bit nonce
      *              - const DilithiumModeConstants& mode: reference to dilihtium mode values
      **************************************************/
      void poly_uniform_gamma1(const secure_vector<uint8_t>& seed, uint16_t nonce, const DilithiumModeConstants& mode) {
         auto buf = mode.ExpandMask(seed, nonce);

         Polynomial::polyz_unpack(*this, buf.data(), mode);
      }

      /*************************************************
      * Name:        poly_decompose
      *
      * Description: For all coefficients c of the input polynomial,
      *              compute high and low bits c0, c1 such c mod Q = c1*ALPHA + c0
      *              with -ALPHA/2 < c0 <= ALPHA/2 except c1 = (Q-1)/ALPHA where we
      *              set c1 = 0 and -ALPHA/2 <= c0 = c mod Q - Q < 0.
      *              Assumes coefficients to be standard representatives.
      *
      * Arguments:   - Polynomial& a1: reference to output polynomial with coefficients c1
      *              - Polynomial& a0: reference to output polynomial with coefficients c0
      *              - const DilithiumModeConstants& mode: reference to dilihtium mode values
      **************************************************/
      void poly_decompose(Polynomial& a1, Polynomial& a0, const DilithiumModeConstants& mode) const {
         for(size_t i = 0; i < DilithiumModeConstants::N; ++i) {
            a1.m_coeffs[i] = Polynomial::decompose(&a0.m_coeffs[i], m_coeffs[i], mode);
         }
      }

      /*************************************************
      * Name:        poly_shiftl
      *
      * Description: Multiply polynomial by 2^D without modular reduction. Assumes
      *              input coefficients to be less than 2^{31-D} in absolute value.
      *
      * Arguments:   - Polynomial& a: pointer to input/output polynomial
      **************************************************/
      void poly_shiftl() {
         for(size_t i = 0; i < m_coeffs.size(); ++i) {
            m_coeffs[i] <<= DilithiumModeConstants::D;
         }
      }

      /*************************************************
      * Name:        polyw1_pack
      *
      * Description: Bit-pack polynomial w1 with coefficients in [0,15] or [0,43].
      *              Input coefficients are assumed to be standard representatives.
      *
      * Arguments:   - uint8_t *r: pointer to output byte array with at least
      *                            POLYW1_PACKEDBYTES bytes
      *           - const DilithiumModeConstants& mode: reference to dilihtium mode values
      **************************************************/
      void polyw1_pack(uint8_t* r, const DilithiumModeConstants& mode) {
         if(mode.gamma2() == (DilithiumModeConstants::Q - 1) / 88) {
            for(size_t i = 0; i < DilithiumModeConstants::N / 4; ++i) {
               r[3 * i + 0] = static_cast<uint8_t>(m_coeffs[4 * i + 0]);
               r[3 * i + 0] |= static_cast<uint8_t>(m_coeffs[4 * i + 1] << 6);
               r[3 * i + 1] = static_cast<uint8_t>(m_coeffs[4 * i + 1] >> 2);
               r[3 * i + 1] |= static_cast<uint8_t>(m_coeffs[4 * i + 2] << 4);
               r[3 * i + 2] = static_cast<uint8_t>(m_coeffs[4 * i + 2] >> 4);
               r[3 * i + 2] |= static_cast<uint8_t>(m_coeffs[4 * i + 3] << 2);
            }
         } else {
            BOTAN_ASSERT_NOMSG(mode.gamma2() == (DilithiumModeConstants::Q - 1) / 32);
            for(size_t i = 0; i < DilithiumModeConstants::N / 2; ++i) {
               r[i] = static_cast<uint8_t>(m_coeffs[2 * i + 0] | (m_coeffs[2 * i + 1] << 4));
            }
         }
      }

      /*************************************************
      * Name:        polyeta_unpack
      *
      * Description: Unpack polynomial with coefficients in [-ETA,ETA].
      *
      * Arguments:   - Polynomial& r: reference to output polynomial
      *              - const uint8_t *a: byte array with bit-packed_t1 polynomial
      *           - const DilithiumModeConstants& mode: reference to dilihtium mode values
      **************************************************/
      static Polynomial polyeta_unpack(std::span<const uint8_t> a, const DilithiumModeConstants& mode) {
         Polynomial r;

         switch(mode.eta()) {
            case DilithiumEta::Eta2: {
               for(size_t i = 0; i < DilithiumModeConstants::N / 8; ++i) {
                  r.m_coeffs[8 * i + 0] = (a[3 * i + 0] >> 0) & 7;
                  r.m_coeffs[8 * i + 1] = (a[3 * i + 0] >> 3) & 7;
                  r.m_coeffs[8 * i + 2] = ((a[3 * i + 0] >> 6) | (a[3 * i + 1] << 2)) & 7;
                  r.m_coeffs[8 * i + 3] = (a[3 * i + 1] >> 1) & 7;
                  r.m_coeffs[8 * i + 4] = (a[3 * i + 1] >> 4) & 7;
                  r.m_coeffs[8 * i + 5] = ((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 7;
                  r.m_coeffs[8 * i + 6] = (a[3 * i + 2] >> 2) & 7;
                  r.m_coeffs[8 * i + 7] = (a[3 * i + 2] >> 5) & 7;

                  r.m_coeffs[8 * i + 0] = static_cast<uint8_t>(mode.eta()) - r.m_coeffs[8 * i + 0];
                  r.m_coeffs[8 * i + 1] = static_cast<uint8_t>(mode.eta()) - r.m_coeffs[8 * i + 1];
                  r.m_coeffs[8 * i + 2] = static_cast<uint8_t>(mode.eta()) - r.m_coeffs[8 * i + 2];
                  r.m_coeffs[8 * i + 3] = static_cast<uint8_t>(mode.eta()) - r.m_coeffs[8 * i + 3];
                  r.m_coeffs[8 * i + 4] = static_cast<uint8_t>(mode.eta()) - r.m_coeffs[8 * i + 4];
                  r.m_coeffs[8 * i + 5] = static_cast<uint8_t>(mode.eta()) - r.m_coeffs[8 * i + 5];
                  r.m_coeffs[8 * i + 6] = static_cast<uint8_t>(mode.eta()) - r.m_coeffs[8 * i + 6];
                  r.m_coeffs[8 * i + 7] = static_cast<uint8_t>(mode.eta()) - r.m_coeffs[8 * i + 7];
               }
            } break;
            case DilithiumEta::Eta4: {
               for(size_t i = 0; i < DilithiumModeConstants::N / 2; ++i) {
                  r.m_coeffs[2 * i + 0] = a[i] & 0x0F;
                  r.m_coeffs[2 * i + 1] = a[i] >> 4;
                  r.m_coeffs[2 * i + 0] = static_cast<uint8_t>(mode.eta()) - r.m_coeffs[2 * i + 0];
                  r.m_coeffs[2 * i + 1] = static_cast<uint8_t>(mode.eta()) - r.m_coeffs[2 * i + 1];
               }
            } break;
         }

         return r;
      }

      /*************************************************
      * Name:        polyeta_pack
      *
      * Description: Bit-pack polynomial with coefficients in [-ETA,ETA].
      *
      * Arguments:   - uint8_t *r: pointer to output byte array with at least
      *                            POLYETA_PACKEDBYTES bytes
      *              - const Polynomial& a: pointer to input polynomial
      *           - const DilithiumModeConstants& mode: reference for dilithium mode values
      **************************************************/
      void polyeta_pack(uint8_t* r, const DilithiumModeConstants& mode) const {
         uint8_t t[8];

         switch(mode.eta()) {
            case DilithiumEta::Eta2: {
               for(size_t i = 0; i < DilithiumModeConstants::N / 8; ++i) {
                  t[0] = static_cast<uint8_t>(mode.eta() - m_coeffs[8 * i + 0]);
                  t[1] = static_cast<uint8_t>(mode.eta() - m_coeffs[8 * i + 1]);
                  t[2] = static_cast<uint8_t>(mode.eta() - m_coeffs[8 * i + 2]);
                  t[3] = static_cast<uint8_t>(mode.eta() - m_coeffs[8 * i + 3]);
                  t[4] = static_cast<uint8_t>(mode.eta() - m_coeffs[8 * i + 4]);
                  t[5] = static_cast<uint8_t>(mode.eta() - m_coeffs[8 * i + 5]);
                  t[6] = static_cast<uint8_t>(mode.eta() - m_coeffs[8 * i + 6]);
                  t[7] = static_cast<uint8_t>(mode.eta() - m_coeffs[8 * i + 7]);

                  r[3 * i + 0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
                  r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
                  r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
               }
            } break;
            case DilithiumEta::Eta4: {
               for(size_t i = 0; i < DilithiumModeConstants::N / 2; ++i) {
                  t[0] = static_cast<uint8_t>(mode.eta() - m_coeffs[2 * i + 0]);
                  t[1] = static_cast<uint8_t>(mode.eta() - m_coeffs[2 * i + 1]);
                  r[i] = static_cast<uint8_t>(t[0] | (t[1] << 4));
               }
            } break;
         }
      }

      /*************************************************
      * Name:        polyt0_unpack
      *
      * Description: Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
      *
      * Arguments:   - poly *r: pointer to output polynomial
      *              - const uint8_t *a: byte array with bit-packed_t1 polynomial
      **************************************************/
      static Polynomial polyt0_unpack(std::span<const uint8_t> a) {
         Polynomial r;

         for(size_t i = 0; i < DilithiumModeConstants::N / 8; ++i) {
            r.m_coeffs[8 * i + 0] = a[13 * i + 0];
            r.m_coeffs[8 * i + 0] |= static_cast<uint32_t>(a[13 * i + 1]) << 8;
            r.m_coeffs[8 * i + 0] &= 0x1FFF;

            r.m_coeffs[8 * i + 1] = a[13 * i + 1] >> 5;
            r.m_coeffs[8 * i + 1] |= static_cast<uint32_t>(a[13 * i + 2]) << 3;
            r.m_coeffs[8 * i + 1] |= static_cast<uint32_t>(a[13 * i + 3]) << 11;
            r.m_coeffs[8 * i + 1] &= 0x1FFF;

            r.m_coeffs[8 * i + 2] = a[13 * i + 3] >> 2;
            r.m_coeffs[8 * i + 2] |= static_cast<uint32_t>(a[13 * i + 4]) << 6;
            r.m_coeffs[8 * i + 2] &= 0x1FFF;

            r.m_coeffs[8 * i + 3] = a[13 * i + 4] >> 7;
            r.m_coeffs[8 * i + 3] |= static_cast<uint32_t>(a[13 * i + 5]) << 1;
            r.m_coeffs[8 * i + 3] |= static_cast<uint32_t>(a[13 * i + 6]) << 9;
            r.m_coeffs[8 * i + 3] &= 0x1FFF;

            r.m_coeffs[8 * i + 4] = a[13 * i + 6] >> 4;
            r.m_coeffs[8 * i + 4] |= static_cast<uint32_t>(a[13 * i + 7]) << 4;
            r.m_coeffs[8 * i + 4] |= static_cast<uint32_t>(a[13 * i + 8]) << 12;
            r.m_coeffs[8 * i + 4] &= 0x1FFF;

            r.m_coeffs[8 * i + 5] = a[13 * i + 8] >> 1;
            r.m_coeffs[8 * i + 5] |= static_cast<uint32_t>(a[13 * i + 9]) << 7;
            r.m_coeffs[8 * i + 5] &= 0x1FFF;

            r.m_coeffs[8 * i + 6] = a[13 * i + 9] >> 6;
            r.m_coeffs[8 * i + 6] |= static_cast<uint32_t>(a[13 * i + 10]) << 2;
            r.m_coeffs[8 * i + 6] |= static_cast<uint32_t>(a[13 * i + 11]) << 10;
            r.m_coeffs[8 * i + 6] &= 0x1FFF;

            r.m_coeffs[8 * i + 7] = a[13 * i + 11] >> 3;
            r.m_coeffs[8 * i + 7] |= static_cast<uint32_t>(a[13 * i + 12]) << 5;
            r.m_coeffs[8 * i + 7] &= 0x1FFF;

            r.m_coeffs[8 * i + 0] = (1 << (DilithiumModeConstants::D - 1)) - r.m_coeffs[8 * i + 0];
            r.m_coeffs[8 * i + 1] = (1 << (DilithiumModeConstants::D - 1)) - r.m_coeffs[8 * i + 1];
            r.m_coeffs[8 * i + 2] = (1 << (DilithiumModeConstants::D - 1)) - r.m_coeffs[8 * i + 2];
            r.m_coeffs[8 * i + 3] = (1 << (DilithiumModeConstants::D - 1)) - r.m_coeffs[8 * i + 3];
            r.m_coeffs[8 * i + 4] = (1 << (DilithiumModeConstants::D - 1)) - r.m_coeffs[8 * i + 4];
            r.m_coeffs[8 * i + 5] = (1 << (DilithiumModeConstants::D - 1)) - r.m_coeffs[8 * i + 5];
            r.m_coeffs[8 * i + 6] = (1 << (DilithiumModeConstants::D - 1)) - r.m_coeffs[8 * i + 6];
            r.m_coeffs[8 * i + 7] = (1 << (DilithiumModeConstants::D - 1)) - r.m_coeffs[8 * i + 7];
         }

         return r;
      }

      /*************************************************
      * Name:        polyt0_pack
      *
      * Description: Bit-pack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
      *
      * Arguments:   - uint8_t *r: pointer to output byte array with at least
      *                            POLYT0_PACKEDBYTES bytes
      *              - const Polynomial& a: reference to input polynomial
      **************************************************/
      void polyt0_pack(uint8_t* r) const {
         uint32_t t[8];
         for(size_t i = 0; i < DilithiumModeConstants::N / 8; ++i) {
            t[0] = (1 << (DilithiumModeConstants::D - 1)) - m_coeffs[8 * i + 0];
            t[1] = (1 << (DilithiumModeConstants::D - 1)) - m_coeffs[8 * i + 1];
            t[2] = (1 << (DilithiumModeConstants::D - 1)) - m_coeffs[8 * i + 2];
            t[3] = (1 << (DilithiumModeConstants::D - 1)) - m_coeffs[8 * i + 3];
            t[4] = (1 << (DilithiumModeConstants::D - 1)) - m_coeffs[8 * i + 4];
            t[5] = (1 << (DilithiumModeConstants::D - 1)) - m_coeffs[8 * i + 5];
            t[6] = (1 << (DilithiumModeConstants::D - 1)) - m_coeffs[8 * i + 6];
            t[7] = (1 << (DilithiumModeConstants::D - 1)) - m_coeffs[8 * i + 7];

            r[13 * i + 0] = static_cast<uint8_t>(t[0]);
            r[13 * i + 1] = static_cast<uint8_t>(t[0] >> 8);
            r[13 * i + 1] |= static_cast<uint8_t>(t[1] << 5);
            r[13 * i + 2] = static_cast<uint8_t>(t[1] >> 3);
            r[13 * i + 3] = static_cast<uint8_t>(t[1] >> 11);
            r[13 * i + 3] |= static_cast<uint8_t>(t[2] << 2);
            r[13 * i + 4] = static_cast<uint8_t>(t[2] >> 6);
            r[13 * i + 4] |= static_cast<uint8_t>(t[3] << 7);
            r[13 * i + 5] = static_cast<uint8_t>(t[3] >> 1);
            r[13 * i + 6] = static_cast<uint8_t>(t[3] >> 9);
            r[13 * i + 6] |= static_cast<uint8_t>(t[4] << 4);
            r[13 * i + 7] = static_cast<uint8_t>(t[4] >> 4);
            r[13 * i + 8] = static_cast<uint8_t>(t[4] >> 12);
            r[13 * i + 8] |= static_cast<uint8_t>(t[5] << 1);
            r[13 * i + 9] = static_cast<uint8_t>(t[5] >> 7);
            r[13 * i + 9] |= static_cast<uint8_t>(t[6] << 6);
            r[13 * i + 10] = static_cast<uint8_t>(t[6] >> 2);
            r[13 * i + 11] = static_cast<uint8_t>(t[6] >> 10);
            r[13 * i + 11] |= static_cast<uint8_t>(t[7] << 3);
            r[13 * i + 12] = static_cast<uint8_t>(t[7] >> 5);
         }
      }

      /*************************************************
      * Name:        polyz_unpack
      *
      * Description: Unpack polynomial z with coefficients
      *              in [-(GAMMA1 - 1), GAMMA1].
      *
      * Arguments:   - Polynomial& r: pointer to output polynomial
      *              - const uint8_t *a: byte array with bit-packed_t1 polynomial
      *              - const DilithiumModeConstants& mode: reference to dilihtium mode values
      **************************************************/
      static void polyz_unpack(Polynomial& r, const uint8_t* a, const DilithiumModeConstants& mode) {
         if(mode.gamma1() == (1 << 17)) {
            for(size_t i = 0; i < DilithiumModeConstants::N / 4; ++i) {
               r.m_coeffs[4 * i + 0] = a[9 * i + 0];
               r.m_coeffs[4 * i + 0] |= static_cast<uint32_t>(a[9 * i + 1]) << 8;
               r.m_coeffs[4 * i + 0] |= static_cast<uint32_t>(a[9 * i + 2]) << 16;
               r.m_coeffs[4 * i + 0] &= 0x3FFFF;

               r.m_coeffs[4 * i + 1] = a[9 * i + 2] >> 2;
               r.m_coeffs[4 * i + 1] |= static_cast<uint32_t>(a[9 * i + 3]) << 6;
               r.m_coeffs[4 * i + 1] |= static_cast<uint32_t>(a[9 * i + 4]) << 14;
               r.m_coeffs[4 * i + 1] &= 0x3FFFF;

               r.m_coeffs[4 * i + 2] = a[9 * i + 4] >> 4;
               r.m_coeffs[4 * i + 2] |= static_cast<uint32_t>(a[9 * i + 5]) << 4;
               r.m_coeffs[4 * i + 2] |= static_cast<uint32_t>(a[9 * i + 6]) << 12;
               r.m_coeffs[4 * i + 2] &= 0x3FFFF;

               r.m_coeffs[4 * i + 3] = a[9 * i + 6] >> 6;
               r.m_coeffs[4 * i + 3] |= static_cast<uint32_t>(a[9 * i + 7]) << 2;
               r.m_coeffs[4 * i + 3] |= static_cast<uint32_t>(a[9 * i + 8]) << 10;
               r.m_coeffs[4 * i + 3] &= 0x3FFFF;

               r.m_coeffs[4 * i + 0] = static_cast<uint32_t>(mode.gamma1()) - r.m_coeffs[4 * i + 0];
               r.m_coeffs[4 * i + 1] = static_cast<uint32_t>(mode.gamma1()) - r.m_coeffs[4 * i + 1];
               r.m_coeffs[4 * i + 2] = static_cast<uint32_t>(mode.gamma1()) - r.m_coeffs[4 * i + 2];
               r.m_coeffs[4 * i + 3] = static_cast<uint32_t>(mode.gamma1()) - r.m_coeffs[4 * i + 3];
            }
         } else if(mode.gamma1() == (1 << 19)) {
            for(size_t i = 0; i < DilithiumModeConstants::N / 2; ++i) {
               r.m_coeffs[2 * i + 0] = a[5 * i + 0];
               r.m_coeffs[2 * i + 0] |= static_cast<uint32_t>(a[5 * i + 1]) << 8;
               r.m_coeffs[2 * i + 0] |= static_cast<uint32_t>(a[5 * i + 2]) << 16;
               r.m_coeffs[2 * i + 0] &= 0xFFFFF;

               r.m_coeffs[2 * i + 1] = a[5 * i + 2] >> 4;
               r.m_coeffs[2 * i + 1] |= static_cast<uint32_t>(a[5 * i + 3]) << 4;
               r.m_coeffs[2 * i + 1] |= static_cast<uint32_t>(a[5 * i + 4]) << 12;
               r.m_coeffs[2 * i + 0] &= 0xFFFFF;

               r.m_coeffs[2 * i + 0] = static_cast<uint32_t>(mode.gamma1()) - r.m_coeffs[2 * i + 0];
               r.m_coeffs[2 * i + 1] = static_cast<uint32_t>(mode.gamma1()) - r.m_coeffs[2 * i + 1];
            }
         }
      }

      /*************************************************
      * Name:        polyz_pack
      *
      * Description: Bit-pack polynomial with coefficients
      *              in [-(GAMMA1 - 1), GAMMA1].
      *
      * Arguments:   - uint8_t *r: pointer to output byte array with at least
      *                            POLYZ_PACKEDBYTES bytes
      *           - const DilithiumModeConstants& mode: reference to dilihtium mode values
      **************************************************/
      void polyz_pack(uint8_t* r, const DilithiumModeConstants& mode) const {
         uint32_t t[4];
         if(mode.gamma1() == (1 << 17)) {
            for(size_t i = 0; i < DilithiumModeConstants::N / 4; ++i) {
               t[0] = static_cast<uint32_t>(mode.gamma1()) - m_coeffs[4 * i + 0];
               t[1] = static_cast<uint32_t>(mode.gamma1()) - m_coeffs[4 * i + 1];
               t[2] = static_cast<uint32_t>(mode.gamma1()) - m_coeffs[4 * i + 2];
               t[3] = static_cast<uint32_t>(mode.gamma1()) - m_coeffs[4 * i + 3];

               r[9 * i + 0] = static_cast<uint8_t>(t[0]);
               r[9 * i + 1] = static_cast<uint8_t>(t[0] >> 8);
               r[9 * i + 2] = static_cast<uint8_t>(t[0] >> 16);
               r[9 * i + 2] |= static_cast<uint8_t>(t[1] << 2);
               r[9 * i + 3] = static_cast<uint8_t>(t[1] >> 6);
               r[9 * i + 4] = static_cast<uint8_t>(t[1] >> 14);
               r[9 * i + 4] |= static_cast<uint8_t>(t[2] << 4);
               r[9 * i + 5] = static_cast<uint8_t>(t[2] >> 4);
               r[9 * i + 6] = static_cast<uint8_t>(t[2] >> 12);
               r[9 * i + 6] |= static_cast<uint8_t>(t[3] << 6);
               r[9 * i + 7] = static_cast<uint8_t>(t[3] >> 2);
               r[9 * i + 8] = static_cast<uint8_t>(t[3] >> 10);
            }
         } else if(mode.gamma1() == (1 << 19)) {
            for(size_t i = 0; i < DilithiumModeConstants::N / 2; ++i) {
               t[0] = static_cast<uint32_t>(mode.gamma1()) - m_coeffs[2 * i + 0];
               t[1] = static_cast<uint32_t>(mode.gamma1()) - m_coeffs[2 * i + 1];

               r[5 * i + 0] = static_cast<uint8_t>(t[0]);
               r[5 * i + 1] = static_cast<uint8_t>(t[0] >> 8);
               r[5 * i + 2] = static_cast<uint8_t>(t[0] >> 16);
               r[5 * i + 2] |= static_cast<uint8_t>(t[1] << 4);
               r[5 * i + 3] = static_cast<uint8_t>(t[1] >> 4);
               r[5 * i + 4] = static_cast<uint8_t>(t[1] >> 12);
            }
         }
      }

      /*************************************************
      * Name:        polyt1_unpack
      *
      * Description: Unpack polynomial t1 with 10-bit coefficients.
      *              Output coefficients are standard representatives.
      *
      * Arguments:   - Polynomial& r: pointer to output polynomial
      *              - const uint8_t *a: byte array with bit-packed_t1 polynomial
      **************************************************/
      static void polyt1_unpack(Polynomial& r, const uint8_t* a) {
         for(size_t i = 0; i < DilithiumModeConstants::N / 4; ++i) {
            r.m_coeffs[4 * i + 0] = ((a[5 * i + 0] >> 0) | (static_cast<uint32_t>(a[5 * i + 1]) << 8)) & 0x3FF;
            r.m_coeffs[4 * i + 1] = ((a[5 * i + 1] >> 2) | (static_cast<uint32_t>(a[5 * i + 2]) << 6)) & 0x3FF;
            r.m_coeffs[4 * i + 2] = ((a[5 * i + 2] >> 4) | (static_cast<uint32_t>(a[5 * i + 3]) << 4)) & 0x3FF;
            r.m_coeffs[4 * i + 3] = ((a[5 * i + 3] >> 6) | (static_cast<uint32_t>(a[5 * i + 4]) << 2)) & 0x3FF;
         }
      }

      /*************************************************
      * Name:        polyt1_pack
      *
      * Description: Bit-pack polynomial t1 with coefficients fitting in 10 bits.
      *              Input coefficients are assumed to be standard representatives.
      *
      * Arguments:   - uint8_t *r: pointer to output byte array with at least
      *                            POLYT1_PACKEDBYTES bytes
      **************************************************/
      void polyt1_pack(uint8_t* r) const {
         for(size_t i = 0; i < DilithiumModeConstants::N / 4; ++i) {
            r[5 * i + 0] = static_cast<uint8_t>((m_coeffs[4 * i + 0] >> 0));
            r[5 * i + 1] = static_cast<uint8_t>((m_coeffs[4 * i + 0] >> 8) | (m_coeffs[4 * i + 1] << 2));
            r[5 * i + 2] = static_cast<uint8_t>((m_coeffs[4 * i + 1] >> 6) | (m_coeffs[4 * i + 2] << 4));
            r[5 * i + 3] = static_cast<uint8_t>((m_coeffs[4 * i + 2] >> 4) | (m_coeffs[4 * i + 3] << 6));
            r[5 * i + 4] = static_cast<uint8_t>((m_coeffs[4 * i + 3] >> 2));
         }
      }

      Polynomial() = default;
};

class PolynomialVector {
   public:
      // public member is on purpose
      std::vector<Polynomial> m_vec;

   public:
      PolynomialVector() = default;

      PolynomialVector& operator+=(const PolynomialVector& other) {
         BOTAN_ASSERT_NOMSG(m_vec.size() != other.m_vec.size());
         for(size_t i = 0; i < m_vec.size(); ++i) {
            this->m_vec[i] += other.m_vec[i];
         }
         return *this;
      }

      PolynomialVector& operator-=(const PolynomialVector& other) {
         BOTAN_ASSERT_NOMSG(m_vec.size() == other.m_vec.size());
         for(size_t i = 0; i < this->m_vec.size(); ++i) {
            this->m_vec[i] -= other.m_vec[i];
         }
         return *this;
      }

      explicit PolynomialVector(size_t size) : m_vec(size) {}

      /*************************************************
      * Name:        poly_uniform
      *
      * Description: Sample polynomial with uniformly random coefficients
      *              in [0,Q-1] by performing rejection sampling on the
      *              output stream of SHAKE256(seed|nonce) or AES256CTR(seed,nonce).
      *
      * Arguments:   - const uint8_t seed[]: secure vector with seed of length SEEDBYTES
      *              - uint16_t nonce: 2-byte nonce
      *              - const DilithiumModeConstants& mode: reference to dilihtium mode values
      * Return Polynomial
      **************************************************/
      static Polynomial poly_uniform(const std::vector<uint8_t>& seed,
                                     uint16_t nonce,
                                     const DilithiumModeConstants& mode) {
         Polynomial sample_poly;
         size_t buflen = mode.poly_uniform_nblocks() * mode.stream128_blockbytes();

         std::vector<uint8_t> buf(buflen + 2);

         auto xof = mode.XOF_128(seed, nonce);
         xof->output(std::span(buf).first(buflen));

         size_t ctr = Polynomial::rej_uniform(sample_poly, 0, DilithiumModeConstants::N, buf.data(), buflen);
         size_t off;
         while(ctr < DilithiumModeConstants::N) {
            off = buflen % 3;
            for(size_t i = 0; i < off; ++i) {
               buf[i] = buf[buflen - off + i];
            }

            xof->output(std::span(buf).subspan(off, mode.stream128_blockbytes()));
            buflen = mode.stream128_blockbytes() + off;
            ctr += Polynomial::rej_uniform(sample_poly, ctr, DilithiumModeConstants::N - ctr, buf.data(), buflen);
         }
         return sample_poly;
      }

      static void fill_polyvec_uniform_eta(PolynomialVector& v,
                                           const secure_vector<uint8_t>& seed,
                                           uint16_t nonce,
                                           const DilithiumModeConstants& mode) {
         for(size_t i = 0; i < v.m_vec.size(); ++i) {
            Polynomial::fill_poly_uniform_eta(v.m_vec[i], seed, nonce++, mode);
         }
      }

      /*************************************************
      * Name:        polyvec_pointwise_acc_montgomery
      *
      * Description: Pointwise multiply vectors of polynomials of length L, multiply
      *              resulting vector by 2^{-32} and add (accumulate) polynomials
      *              in it. Input/output vectors are in NTT domain representation.
      *
      * Arguments:   - Polynomial &w: output polynomial
      *              - const Polynomial &u: pointer to first input vector
      *              - const Polynomial &v: pointer to second input vector
      **************************************************/
      static void polyvec_pointwise_acc_montgomery(Polynomial& w,
                                                   const PolynomialVector& u,
                                                   const PolynomialVector& v) {
         BOTAN_ASSERT_NOMSG(u.m_vec.size() == v.m_vec.size());
         BOTAN_ASSERT_NOMSG(!u.m_vec.empty() && !v.m_vec.empty());

         u.m_vec[0].poly_pointwise_montgomery(w, v.m_vec[0]);

         for(size_t i = 1; i < v.m_vec.size(); ++i) {
            Polynomial t;
            u.m_vec[i].poly_pointwise_montgomery(t, v.m_vec[i]);
            w += t;
         }
      }

      /*************************************************
      * Name:        fill_polyvecs_power2round
      *
      * Description: For all coefficients a of polynomials in vector ,
      *              compute a0, a1 such that a mod^+ Q = a1*2^D + a0
      *              with -2^{D-1} < a0 <= 2^{D-1}. Assumes coefficients to be
      *              standard representatives.
      *
      * Arguments:   - PolynomialVector& v1: reference to output vector of polynomials with
      *                              coefficients a1
      *              - PolynomialVector& v0: reference to output vector of polynomials with
      *                              coefficients a0
      *              - const PolynomialVector& v: reference to input vector
      **************************************************/
      static void fill_polyvecs_power2round(PolynomialVector& v1, PolynomialVector& v0, const PolynomialVector& v) {
         BOTAN_ASSERT((v1.m_vec.size() == v0.m_vec.size()) && (v1.m_vec.size() == v.m_vec.size()),
                      "possible buffer overflow! Wrong PolynomialVector sizes.");
         for(size_t i = 0; i < v1.m_vec.size(); ++i) {
            Polynomial::fill_polys_power2round(v1.m_vec[i], v0.m_vec[i], v.m_vec[i]);
         }
      }

      static bool unpack_sig(std::array<uint8_t, DilithiumModeConstants::SEEDBYTES>& c,
                             PolynomialVector& z,
                             PolynomialVector& h,
                             const std::vector<uint8_t>& sig,
                             const DilithiumModeConstants& mode) {
         //const auto& mode = m_pub_key.m_public->mode();
         BOTAN_ASSERT(sig.size() == mode.crypto_bytes(), "invalid signature size");
         size_t position = 0;

         std::copy(sig.begin(), sig.begin() + c.size(), c.begin());

         position += DilithiumModeConstants::SEEDBYTES;

         for(size_t i = 0; i < mode.l(); ++i) {
            Polynomial::polyz_unpack(z.m_vec[i], sig.data() + position + i * mode.polyz_packedbytes(), mode);
         }
         position += mode.l() * mode.polyz_packedbytes();

         /* Decode h */
         size_t k = 0;
         for(size_t i = 0; i < mode.k(); ++i) {
            for(size_t j = 0; j < DilithiumModeConstants::N; ++j) {
               h.m_vec[i].m_coeffs[j] = 0;
            }

            if(sig[position + mode.omega() + i] < k || sig[position + mode.omega() + i] > mode.omega()) {
               return true;
            }

            for(size_t j = k; j < sig[position + mode.omega() + i]; ++j) {
               /* Coefficients are ordered for strong unforgeability */
               if(j > k && sig[position + j] <= sig[position + j - 1]) {
                  return true;
               }
               h.m_vec[i].m_coeffs[sig[position + j]] = 1;
            }

            k = sig[position + mode.omega() + i];
         }

         /* Extra indices are zero for strong unforgeability */
         for(size_t j = k; j < mode.omega(); ++j) {
            if(sig[position + j]) {
               return true;
            }
         }

         return false;
      }

      /*************************************************
      * Name:        generate_hint_polyvec
      *
      * Description: Compute hint vector.
      *
      * Arguments:   - PolynomialVector *h: reference to output vector
      *              - const PolynomialVector *v0: reference to low part of input vector
      *              - const PolynomialVector *v1: reference to high part of input vector
      *           - const DilithiumModeConstants& mode: reference to dilihtium mode values
      *
      * Returns number of 1 bits.
      **************************************************/
      static size_t generate_hint_polyvec(PolynomialVector& h,
                                          const PolynomialVector& v0,
                                          const PolynomialVector& v1,
                                          const DilithiumModeConstants& mode) {
         size_t s = 0;

         for(size_t i = 0; i < h.m_vec.size(); ++i) {
            s += Polynomial::generate_hint_polynomial(h.m_vec[i], v0.m_vec[i], v1.m_vec[i], mode);
         }

         return s;
      }

      /*************************************************
      * Name:        ntt
      *
      * Description: Forward NTT of all polynomials in vector. Output
      *              coefficients can be up to 16*Q larger than input coefficients.
      **************************************************/
      void ntt() {
         for(auto& i : m_vec) {
            i.ntt();
         }
      }

      /*************************************************
      * Name:        polyveck_decompose
      *
      * Description: For all coefficients a of polynomials in vector,
      *              compute high and low bits a0, a1 such a mod^+ Q = a1*ALPHA + a0
      *              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q-1)/ALPHA where we
      *              set a1 = 0 and -ALPHA/2 <= a0 = a mod Q - Q < 0.
      *              Assumes coefficients to be standard representatives.
      *
      * Arguments:   - PolynomialVector& v1: reference to output vector of polynomials with
      *                              coefficients a1
      *              - PolynomialVector& v0: reference to output vector of polynomials with
      *                              coefficients a0
      *              - const PolynomialVector& v: reference to input vector
      **************************************************/
      std::tuple<PolynomialVector, PolynomialVector> polyvec_decompose(const DilithiumModeConstants& mode) {
         PolynomialVector v1(mode.k());
         PolynomialVector v0(mode.k());

         for(size_t i = 0; i < m_vec.size(); ++i) {
            m_vec[i].poly_decompose(v1.m_vec[i], v0.m_vec[i], mode);
         }
         return std::make_tuple(v1, v0);
      }

      /*************************************************
      * Name:        reduce
      *
      * Description: Reduce coefficients of polynomials in vector
      *              to representatives in [-6283009,6283007].
      **************************************************/
      void reduce() {
         for(auto& i : m_vec) {
            i.poly_reduce();
         }
      }

      /*************************************************
      * Name:        invntt_tomont
      *
      * Description: Inverse NTT and multiplication by 2^{32} of polynomials
      *              in vector. Input coefficients need to be less
      *              than 2*Q.
      **************************************************/
      void invntt_tomont() {
         for(auto& i : m_vec) {
            i.poly_invntt_tomont();
         }
      }

      /*************************************************
      * Name:        add_polyvec
      *
      * Description: Add vectors of polynomials .
      *              No modular reduction is performed.
      *
      * Arguments:   - const PolynomialVector *v: pointer to second summand
      *              - const PolynomialVector *u: pointer to first summand
      **************************************************/
      void add_polyvec(const PolynomialVector& v) {
         BOTAN_ASSERT((m_vec.size() == v.m_vec.size()), "possible buffer overflow! Wrong PolynomialVector sizes.");
         for(size_t i = 0; i < m_vec.size(); ++i) {
            m_vec[i] += v.m_vec[i];
         }
      }

      /*************************************************
      * Name:        cadd_q
      *
      * Description: For all coefficients of polynomials in vector
      *              add Q if coefficient is negative.
      **************************************************/
      void cadd_q() {
         for(auto& i : m_vec) {
            i.cadd_q();
         }
      }

      void polyvecl_uniform_gamma1(const secure_vector<uint8_t>& seed,
                                   uint16_t nonce,
                                   const DilithiumModeConstants& mode) {
         BOTAN_ASSERT_NOMSG(m_vec.size() <= std::numeric_limits<uint16_t>::max());
         for(uint16_t i = 0; i < static_cast<uint16_t>(this->m_vec.size()); ++i) {
            m_vec[i].poly_uniform_gamma1(seed, mode.l() * nonce + i, mode);
         }
      }

      void polyvec_pointwise_poly_montgomery(PolynomialVector& r, const Polynomial& a) {
         for(size_t i = 0; i < m_vec.size(); ++i) {
            m_vec[i].poly_pointwise_montgomery(r.m_vec[i], a);
         }
      }

      /*************************************************
      * Name:        polyvecl_chknorm
      *
      * Description: Check infinity norm of polynomials in vector of length L.
      *              Assumes input polyvecl to be reduced by polyvecl_reduce().
      *
      * Arguments:   - size_t B: norm bound
      *
      * Returns false if norm of all polynomials is strictly smaller than B <= (Q-1)/8
      * and true otherwise.
      **************************************************/
      bool polyvec_chknorm(size_t bound) {
         for(auto& i : m_vec) {
            if(Polynomial::poly_chknorm(i, bound)) {
               return true;
            }
         }
         return false;
      }

      /*************************************************
      * Name:        polyvec_shiftl
      *
      * Description: Multiply vector of polynomials by 2^D without modular
      *              reduction. Assumes input coefficients to be less than 2^{31-D}.
      **************************************************/
      void polyvec_shiftl() {
         for(auto& i : m_vec) {
            i.poly_shiftl();
         }
      }

      /*************************************************
      * Name:        polyvec_use_hint
      *
      * Description: Use hint vector to correct the high bits of input vector.
      *
      * Arguments:   - PolynomialVector& w: reference to output vector of polynomials with
      *                             corrected high bits
      *              - const PolynomialVector& u: reference to input vector
      *              - const PolynomialVector& h: reference to input hint vector
      *           - const DilithiumModeConstants& mode: reference to dilihtium mode values
      **************************************************/
      void polyvec_use_hint(PolynomialVector& w, const PolynomialVector& h, const DilithiumModeConstants& mode) {
         for(size_t i = 0; i < w.m_vec.size(); ++i) {
            Polynomial::poly_use_hint(w.m_vec[i], m_vec[i], h.m_vec[i], mode);
         }
      }

      secure_vector<uint8_t> polyvec_pack_eta(const DilithiumModeConstants& mode) const {
         secure_vector<uint8_t> packed_eta(mode.polyeta_packedbytes() * m_vec.size());
         for(size_t i = 0; i < m_vec.size(); ++i) {
            m_vec[i].polyeta_pack(packed_eta.data() + mode.polyeta_packedbytes() * i, mode);
         }
         return packed_eta;
      }

      static PolynomialVector unpack_eta(std::span<const uint8_t> buffer,
                                         size_t size,
                                         const DilithiumModeConstants& mode) {
         BOTAN_ARG_CHECK(buffer.size() == mode.polyeta_packedbytes() * size, "Invalid buffer size");

         PolynomialVector pv(size);
         for(size_t i = 0; i < pv.m_vec.size(); ++i) {
            pv.m_vec[i] = Polynomial::polyeta_unpack(
               buffer.subspan(i * mode.polyeta_packedbytes(), mode.polyeta_packedbytes()), mode);
         }
         return pv;
      }

      secure_vector<uint8_t> polyvec_pack_t0() const {
         secure_vector<uint8_t> packed_t0(m_vec.size() * DilithiumModeConstants::POLYT0_PACKEDBYTES);
         for(size_t i = 0; i < m_vec.size(); ++i) {
            m_vec[i].polyt0_pack(packed_t0.data() + i * DilithiumModeConstants::POLYT0_PACKEDBYTES);
         }
         return packed_t0;
      }

      static PolynomialVector unpack_t0(std::span<const uint8_t> buffer, const DilithiumModeConstants& mode) {
         BOTAN_ARG_CHECK(static_cast<int32_t>(buffer.size()) == DilithiumModeConstants::POLYT0_PACKEDBYTES * mode.k(),
                         "Invalid buffer size");

         PolynomialVector t0(mode.k());
         for(size_t i = 0; i < t0.m_vec.size(); ++i) {
            t0.m_vec[i] = Polynomial::polyt0_unpack(buffer.subspan(i * DilithiumModeConstants::POLYT0_PACKEDBYTES,
                                                                   DilithiumModeConstants::POLYT0_PACKEDBYTES));
         }
         return t0;
      }

      std::vector<uint8_t> polyvec_pack_t1() const {
         std::vector<uint8_t> packed_t1(m_vec.size() * DilithiumModeConstants::POLYT1_PACKEDBYTES);
         for(size_t i = 0; i < m_vec.size(); ++i) {
            m_vec[i].polyt1_pack(packed_t1.data() + i * DilithiumModeConstants::POLYT1_PACKEDBYTES);
         }
         return packed_t1;
      }

      static PolynomialVector unpack_t1(std::span<const uint8_t> packed_t1, const DilithiumModeConstants& mode) {
         BOTAN_ARG_CHECK(
            static_cast<int32_t>(packed_t1.size()) == DilithiumModeConstants::POLYT1_PACKEDBYTES * mode.k(),
            "Invalid buffer size");

         PolynomialVector t1(mode.k());
         for(size_t i = 0; i < t1.m_vec.size(); ++i) {
            Polynomial::polyt1_unpack(t1.m_vec[i], packed_t1.data() + i * DilithiumModeConstants::POLYT1_PACKEDBYTES);
         }
         return t1;
      }

      std::vector<uint8_t> polyvec_pack_w1(const DilithiumModeConstants& mode) {
         std::vector<uint8_t> packed_w1(mode.polyw1_packedbytes() * m_vec.size());
         for(size_t i = 0; i < m_vec.size(); ++i) {
            m_vec[i].polyw1_pack(packed_w1.data() + i * mode.polyw1_packedbytes(), mode);
         }
         return packed_w1;
      }

      static PolynomialVector polyvec_unpack_z(const uint8_t* packed_z, const DilithiumModeConstants& mode) {
         PolynomialVector z(mode.l());
         for(size_t i = 0; i < z.m_vec.size(); ++i) {
            Polynomial::polyz_unpack(z.m_vec[i], packed_z + i * mode.polyz_packedbytes(), mode);
         }
         return z;
      }

      /*************************************************
      * Name:        generate_polyvec_matrix_pointwise_montgomery
      *
      * Description: Generates a PolynomialVector based on a matrix using pointwise montgomery acc
      *
      * Arguments:   - const std::vector<uint8_t>& rho[]: byte array containing seed rho
      *              - const DilithiumModeConstants& mode: reference to dilihtium mode values
      * Returns a PolynomialVector
      **************************************************/
      static PolynomialVector generate_polyvec_matrix_pointwise_montgomery(const std::vector<PolynomialVector>& mat,
                                                                           const PolynomialVector& v,
                                                                           const DilithiumModeConstants& mode) {
         PolynomialVector t(mode.k());
         for(size_t i = 0; i < mode.k(); ++i) {
            PolynomialVector::polyvec_pointwise_acc_montgomery(t.m_vec[i], mat[i], v);
         }
         return t;
      }
};

class PolynomialMatrix {
   private:
      // Matrix of length k holding a polynomialVector of size l, which has N coeffs
      std::vector<PolynomialVector> m_mat;

      explicit PolynomialMatrix(const DilithiumModeConstants& mode) : m_mat(mode.k(), PolynomialVector(mode.l())) {}

   public:
      PolynomialMatrix() = delete;

      /*************************************************
      * Name:        generate_matrix
      *
      * Description: Implementation of generate_matrix. Generates matrix A with uniformly
      *              random coefficients a_{i,j} by performing rejection
      *              sampling on the output stream of SHAKE128(rho|j|i)
      *              or AES256CTR(rho,j|i).
      *
      * Arguments:   - const std::vector<uint8_t>& rho[]: byte array containing seed rho
      *              - const DilithiumModeConstants& mode: reference to dilihtium mode values
      * Returns the output matrix mat[k]
      **************************************************/
      static PolynomialMatrix generate_matrix(const std::vector<uint8_t>& rho, const DilithiumModeConstants& mode) {
         BOTAN_ASSERT(rho.size() >= DilithiumModeConstants::SEEDBYTES, "wrong byte length for rho/seed");

         PolynomialMatrix matrix(mode);
         for(uint16_t i = 0; i < mode.k(); ++i) {
            for(uint16_t j = 0; j < mode.l(); ++j) {
               matrix.m_mat[i].m_vec[j] = PolynomialVector::poly_uniform(rho, (i << 8) + j, mode);
            }
         }
         return matrix;
      }

      const std::vector<PolynomialVector>& get_matrix() const { return m_mat; }
};
}  // namespace Botan::Dilithium

#endif
