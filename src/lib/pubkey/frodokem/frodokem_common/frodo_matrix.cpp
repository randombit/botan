/*
 * FrodoKEM matrix logic
 * Based on the MIT licensed reference implementation by the designers
 * (https://github.com/microsoft/PQCrypto-LWEKE/tree/master)
 *
 * The Fellowship of the FrodoKEM:
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/frodo_matrix.h>

#include <botan/assert.h>
#include <botan/xof.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/frodo_constants.h>
#include <botan/internal/loadstor.h>
#include <array>
#include <bit>
#include <span>
#include <utility>
#include <vector>

#if defined(BOTAN_HAS_FRODOKEM_AES)
   #include <botan/internal/frodo_aes_generator.h>
#endif

#if defined(BOTAN_HAS_FRODOKEM_SHAKE)
   #include <botan/internal/frodo_shake_generator.h>
#endif

namespace Botan {

namespace {

secure_vector<uint16_t> make_elements_vector(const FrodoMatrix::Dimensions& dimensions) {
   return secure_vector<uint16_t>(static_cast<size_t>(std::get<0>(dimensions)) * std::get<1>(dimensions));
}

// Number of rows of A generated at once. Any remainder chunk is still a
// multiple of the row batch widths of the multiplication loops (4 and 8),
// since the FrodoKEM row counts (640, 976, 1344) are all multiples of 16.
//
// For SHAKE large chunks amortize the per-batch dispatch cost of the
// threaded hash engine. AES sees no cross-row batching benefit, so a
// small chunk keeps the buffer cache resident.
size_t frodo_row_chunk(const FrodoKEMConstants& constants) {
   return constants.mode().is_aes() ? 16 : 512;
}

std::function<void(std::span<uint8_t> out, uint16_t first_row, size_t nrows)> make_row_generator(
   const FrodoKEMConstants& constants, StrongSpan<const FrodoSeedA> seed_a) {
#if defined(BOTAN_HAS_FRODOKEM_AES)
   if(constants.mode().is_aes()) {
      return create_aes_row_generator(constants, seed_a);
   }
#endif

#if defined(BOTAN_HAS_FRODOKEM_SHAKE)
   if(constants.mode().is_shake()) {
      return create_shake_row_generator(constants, seed_a);
   }
#endif

   // If we don't have AES in this build, the instantiation of the FrodoKEM instance
   // is blocked upstream already. Hence, assert is save here.
   BOTAN_ASSERT_UNREACHABLE();
}

}  // namespace

FrodoMatrix FrodoMatrix::sample(const FrodoKEMConstants& constants,
                                const Dimensions& dimensions,
                                StrongSpan<const FrodoSampleR> r) {
   BOTAN_ASSERT_NOMSG(r.size() % 2 == 0);
   const auto n = r.size() / 2;

   auto elements = make_elements_vector(dimensions);
   BOTAN_ASSERT_NOMSG(n == elements.size());

   load_le<uint16_t>(elements.data(), r.data(), n);

   std::array<uint16_t, 16> cdf{};
   const size_t cdf_len = constants.cdf_table_len();
   BOTAN_ASSERT_NOMSG(cdf_len <= cdf.size());
   for(size_t j = 0; j != cdf_len; ++j) {
      cdf[j] = constants.cdf_table_at(j);
   }

   for(auto& elem : elements) {
      const auto prnd = CT::value_barrier(static_cast<uint16_t>(elem >> 1));  // Drop the least significant bit
      const auto sign = CT::Mask<uint16_t>::expand_bit(elem, 0);              // Pick the least significant bit

      uint32_t sample = 0;  // Avoid integral promotion

      // No need to compare with the last value.
      for(size_t j = 0; j < cdf_len - 1; ++j) {
         // Constant time comparison: 1 if CDF_TABLE[j] < s, 0 otherwise.
         sample += CT::Mask<uint16_t>::is_lt(cdf[j], prnd).if_set_return(1);
      }
      // Assuming that sign is either 0 or 1, flips sample iff sign = 1
      const uint16_t sample_u16 = static_cast<uint16_t>(sample);

      elem = sign.select(~sample_u16 + 1, sample_u16);
   }

   return FrodoMatrix(dimensions, std::move(elements));
}

std::function<FrodoMatrix(const FrodoMatrix::Dimensions& dimensions)> FrodoMatrix::make_sample_generator(
   const FrodoKEMConstants& constants, Botan::XOF& shake) {
   return [&constants, &shake](const FrodoMatrix::Dimensions& dimensions) mutable {
      return sample(constants,
                    dimensions,
                    shake.output<FrodoSampleR>(sizeof(uint16_t) * std::get<0>(dimensions) * std::get<1>(dimensions)));
   };
}

FrodoMatrix::FrodoMatrix(Dimensions dims) :
      m_dim1(std::get<0>(dims)), m_dim2(std::get<1>(dims)), m_elements(make_elements_vector(dims)) {}

FrodoMatrix FrodoMatrix::mul_add_as_plus_e(const FrodoKEMConstants& constants,
                                           const FrodoMatrix& s,
                                           const FrodoMatrix& e,
                                           StrongSpan<const FrodoSeedA> seed_a) {
   BOTAN_ASSERT(std::get<0>(e.dimensions()) == std::get<1>(s.dimensions()) &&
                   std::get<1>(e.dimensions()) == std::get<0>(s.dimensions()),
                "FrodoMatrix dimension mismatch of E and S");
   BOTAN_ASSERT(std::get<0>(e.dimensions()) == constants.n() && std::get<1>(e.dimensions()) == constants.n_bar(),
                "FrodoMatrix dimension mismatch of new matrix dimensions and E");

   auto elements = make_elements_vector(e.dimensions());
   auto row_generator = make_row_generator(constants, seed_a);

   /*
   We generate the rows of A in batched chunks, each row containing n 16-bit values.
   a_row_data contains the 16-bit values of the current chunk of rows.
   a_row_data_bytes represents the corresponding bytes.
   */
   const size_t row_chunk = frodo_row_chunk(constants);
   std::vector<uint16_t> a_row_data(row_chunk * constants.n(), 0);
   // TODO: maybe use std::as_bytes() instead
   //       (take extra care, as it produces a std::span<std::byte>)
   const std::span<uint8_t> a_row_data_bytes(reinterpret_cast<uint8_t*>(a_row_data.data()),
                                             sizeof(uint16_t) * a_row_data.size());

   for(size_t i = 0; i < constants.n(); i += row_chunk) {
      const size_t rows = std::min(row_chunk, constants.n() - i);

      row_generator(a_row_data_bytes.first(rows * constants.n() * sizeof(uint16_t)), static_cast<uint16_t>(i), rows);

      // On little-endian the generated bytes already have the in-memory
      // layout of the 16-bit elements
      if constexpr(std::endian::native == std::endian::big) {
         load_le<uint16_t>(a_row_data.data(), a_row_data_bytes.data(), rows * constants.n());
      }

      // Process 4 rows of the chunk per pass
      for(size_t r = 0; r < rows; r += 4) {
         for(size_t k = 0; k < constants.n_bar(); ++k) {
            std::array<uint16_t, 4> sum = {0};
            for(size_t j = 0; j < constants.n(); ++j) {  // Matrix-vector multiplication
               // Note: we use uint32_t for `sp` to avoid an integral promotion to `int`
               //       when multiplying `sp` with other row values. Otherwise we might
               //       suffer from undefined behaviour due to a signed integer overflow.
               // See:  https://learn.microsoft.com/en-us/cpp/cpp/standard-conversions#integral-promotions
               const uint32_t sp = s.elements_at(k * constants.n() + j);

               // Go through four lines with same sp
               sum[0] += static_cast<uint16_t>(a_row_data[(r + 0) * constants.n() + j] * sp);
               sum[1] += static_cast<uint16_t>(a_row_data[(r + 1) * constants.n() + j] * sp);
               sum[2] += static_cast<uint16_t>(a_row_data[(r + 2) * constants.n() + j] * sp);
               sum[3] += static_cast<uint16_t>(a_row_data[(r + 3) * constants.n() + j] * sp);
            }
            elements.at((i + r + 0) * constants.n_bar() + k) =
               e.elements_at((i + r + 0) * constants.n_bar() + k) + sum.at(0);
            elements.at((i + r + 3) * constants.n_bar() + k) =
               e.elements_at((i + r + 3) * constants.n_bar() + k) + sum.at(3);
            elements.at((i + r + 2) * constants.n_bar() + k) =
               e.elements_at((i + r + 2) * constants.n_bar() + k) + sum.at(2);
            elements.at((i + r + 1) * constants.n_bar() + k) =
               e.elements_at((i + r + 1) * constants.n_bar() + k) + sum.at(1);
         }
      }
   }

   return FrodoMatrix(e.dimensions(), std::move(elements));
}

FrodoMatrix FrodoMatrix::mul_add_sa_plus_e(const FrodoKEMConstants& constants,
                                           const FrodoMatrix& s,
                                           const FrodoMatrix& e,
                                           StrongSpan<const FrodoSeedA> seed_a) {
   BOTAN_ASSERT(std::get<0>(e.dimensions()) == std::get<0>(s.dimensions()) &&
                   std::get<1>(e.dimensions()) == std::get<1>(s.dimensions()),
                "FrodoMatrix dimension mismatch of E and S");
   BOTAN_ASSERT(std::get<0>(e.dimensions()) == constants.n_bar() && std::get<1>(e.dimensions()) == constants.n(),
                "FrodoMatrix dimension mismatch of new matrix dimensions and E");

   auto elements = e.m_elements;
   auto row_generator = make_row_generator(constants, seed_a);

   /*
   We generate the rows of A in batched chunks, each row containing n 16-bit values.
   a_row_data contains the 16-bit values of the current chunk of rows.
   a_row_data_bytes represents the corresponding bytes.
   */
   const size_t row_chunk = frodo_row_chunk(constants);
   std::vector<uint16_t> a_row_data(row_chunk * constants.n(), 0);
   // TODO: maybe use std::as_bytes()
   const std::span<uint8_t> a_row_data_bytes(reinterpret_cast<uint8_t*>(a_row_data.data()),
                                             sizeof(uint16_t) * a_row_data.size());

   // Start matrix multiplication
   for(size_t i = 0; i < constants.n(); i += row_chunk) {
      const size_t rows = std::min(row_chunk, constants.n() - i);

      row_generator(a_row_data_bytes.first(rows * constants.n() * sizeof(uint16_t)), static_cast<uint16_t>(i), rows);

      // On little-endian the generated bytes already have the in-memory
      // layout of the 16-bit elements
      if constexpr(std::endian::native == std::endian::big) {
         load_le<uint16_t>(a_row_data.data(), a_row_data_bytes.data(), rows * constants.n());
      }

      // Process 8 rows of the chunk per pass
      for(size_t r = 0; r < rows; r += 8) {
         for(size_t j = 0; j < constants.n_bar(); ++j) {
            uint16_t sum = 0;
            std::array<uint32_t /* to avoid integral promotion */, 8> sp{};
            for(size_t p = 0; p < 8; ++p) {
               sp[p] = s.elements_at(j * constants.n() + i + r + p);
            }
            for(size_t q = 0; q < constants.n(); ++q) {
               sum = elements[j * constants.n() + q];
               for(size_t p = 0; p < 8; ++p) {
                  sum += static_cast<uint16_t>(sp[p] * a_row_data[(r + p) * constants.n() + q]);
               }
               elements[j * constants.n() + q] = sum;
            }
         }
      }
   }

   return FrodoMatrix(e.dimensions(), std::move(elements));
}

FrodoMatrix FrodoMatrix::mul_add_sb_plus_e(const FrodoKEMConstants& constants,
                                           const FrodoMatrix& b,
                                           const FrodoMatrix& s,
                                           const FrodoMatrix& e) {
   BOTAN_ASSERT(std::get<0>(b.dimensions()) == std::get<1>(s.dimensions()) &&
                   std::get<1>(b.dimensions()) == std::get<0>(s.dimensions()),
                "FrodoMatrix dimension mismatch of B and S");
   BOTAN_ASSERT(std::get<0>(b.dimensions()) == constants.n() && std::get<1>(b.dimensions()) == constants.n_bar(),
                "FrodoMatrix dimension mismatch of B");
   BOTAN_ASSERT(std::get<0>(e.dimensions()) == constants.n_bar() && std::get<1>(e.dimensions()) == constants.n_bar(),
                "FrodoMatrix dimension mismatch of E");

   auto elements = make_elements_vector(e.dimensions());

   for(size_t k = 0; k < constants.n_bar(); ++k) {
      for(size_t i = 0; i < constants.n_bar(); ++i) {
         elements.at(k * constants.n_bar() + i) = e.elements_at(k * constants.n_bar() + i);
         for(size_t j = 0; j < constants.n(); ++j) {
            elements.at(k * constants.n_bar() + i) += static_cast<uint16_t>(
               static_cast<uint32_t /* to avoid integral promotion */>(s.elements_at(k * constants.n() + j)) *
               b.elements_at(j * constants.n_bar() + i));
         }
      }
   }

   return FrodoMatrix(e.dimensions(), std::move(elements));
}

FrodoMatrix FrodoMatrix::encode(const FrodoKEMConstants& constants, StrongSpan<const FrodoPlaintext> in) {
   const uint64_t mask = (uint64_t(1) << constants.b()) - 1;

   const auto dimensions = std::make_tuple<size_t, size_t>(constants.n_bar(), constants.n_bar());
   auto elements = make_elements_vector(dimensions);

   BOTAN_ASSERT_NOMSG(in.size() * 8 == constants.n_bar() * constants.n_bar() * constants.b());

   size_t pos = 0;
   for(size_t i = 0; i < (constants.n_bar() * constants.n_bar()) / 8; ++i) {
      uint64_t temp = 0;
      for(size_t j = 0; j < constants.b(); ++j) {
         temp |= static_cast<uint64_t /* avoiding integral promotion */>(in[i * constants.b() + j]) << (8 * j);
      }
      for(size_t j = 0; j < 8; ++j) {
         elements.at(pos++) = static_cast<uint16_t>((temp & mask) << (constants.d() - constants.b()));  // k*2^(D-B)
         temp >>= constants.b();
      }
   }

   return FrodoMatrix(dimensions, std::move(elements));
}

FrodoMatrix FrodoMatrix::add(const FrodoKEMConstants& constants, const FrodoMatrix& a, const FrodoMatrix& b) {
   // Addition is defined for n_bar x n_bar matrices only
   BOTAN_ASSERT_NOMSG(a.dimensions() == b.dimensions());
   BOTAN_ASSERT_NOMSG(std::get<0>(a.dimensions()) == constants.n_bar() &&
                      std::get<1>(a.dimensions()) == constants.n_bar());

   auto elements = make_elements_vector(a.dimensions());

   for(size_t i = 0; i < constants.n_bar() * constants.n_bar(); ++i) {
      elements.at(i) = a.elements_at(i) + b.elements_at(i);
   }

   return FrodoMatrix(a.dimensions(), std::move(elements));
}

FrodoMatrix FrodoMatrix::sub(const FrodoKEMConstants& constants, const FrodoMatrix& a, const FrodoMatrix& b) {
   // Subtraction is defined for n_bar x n_bar matrices only
   BOTAN_ASSERT_NOMSG(a.dimensions() == b.dimensions());
   BOTAN_ASSERT_NOMSG(std::get<0>(a.dimensions()) == constants.n_bar() &&
                      std::get<1>(a.dimensions()) == constants.n_bar());

   auto elements = make_elements_vector(a.dimensions());

   for(size_t i = 0; i < constants.n_bar() * constants.n_bar(); ++i) {
      elements.at(i) = a.elements_at(i) - b.elements_at(i);
   }

   return FrodoMatrix(a.dimensions(), std::move(elements));
}

CT::Mask<uint8_t> FrodoMatrix::constant_time_compare(const FrodoMatrix& other) const {
   BOTAN_ASSERT_NOMSG(dimensions() == other.dimensions());
   // TODO: Possibly use range-based comparison after #3715 is merged
   return CT::is_equal(reinterpret_cast<const uint8_t*>(m_elements.data()),
                       reinterpret_cast<const uint8_t*>(other.m_elements.data()),
                       sizeof(decltype(m_elements)::value_type) * m_elements.size());
}

FrodoMatrix FrodoMatrix::mul_bs(const FrodoKEMConstants& constants, const FrodoMatrix& b, const FrodoMatrix& s) {
   const Dimensions dimensions = {constants.n_bar(), constants.n_bar()};
   auto elements = make_elements_vector(dimensions);

   for(size_t i = 0; i < constants.n_bar(); ++i) {
      for(size_t j = 0; j < constants.n_bar(); ++j) {
         auto& current = elements.at(i * constants.n_bar() + j);
         current = 0;
         for(size_t k = 0; k < constants.n(); ++k) {
            // Explicitly store the values in 32-bit variables to avoid integral promotion
            const uint32_t b_ink = b.elements_at(i * constants.n() + k);

            // Since the input is s^T, we multiply the i-th row of b with the j-th row of s^t
            const uint32_t s_ink = s.elements_at(j * constants.n() + k);

            current += static_cast<uint16_t>(b_ink * s_ink);
         }
      }
   }

   return FrodoMatrix(dimensions, std::move(elements));
}

void FrodoMatrix::pack(const FrodoKEMConstants& constants, StrongSpan<FrodoPackedMatrix> out) const {
   const size_t outlen = packed_size(constants);
   BOTAN_ASSERT_NOMSG(out.size() == outlen);

   // The bit assembly below accumulates into out, so it requires a zeroed destination
   clear_mem(out);

   size_t i = 0;      // whole bytes already filled in
   size_t j = 0;      // whole uint16_t already copied
   uint16_t w = 0;    // the leftover, not yet copied
   uint8_t bits = 0;  // the number of lsb in w

   while(i < outlen && (j < element_count() || ((j == element_count()) && (bits > 0)))) {
      /*
      in: |        |        |********|********|
                            ^
                            j
      w : |   ****|
              ^
             bits
      out:|**|**|**|**|**|**|**|**|* |
                                  ^^
                                  ib
      */
      uint8_t b = 0;  // bits in out[i] already filled in
      while(b < 8) {
         const uint8_t nbits = std::min(static_cast<uint8_t>(8 - b), bits);
         const uint16_t mask = static_cast<uint16_t>(1 << nbits) - 1;
         const auto t = static_cast<uint8_t>((w >> (bits - nbits)) & mask);  // the bits to copy from w to out
         out[i] = out[i] + static_cast<uint8_t>(t << (8 - b - nbits));
         b += nbits;
         bits -= nbits;

         if(bits == 0) {
            if(j < element_count()) {
               w = m_elements.at(j);
               bits = static_cast<uint8_t>(constants.d());
               j++;
            } else {
               break;  // the input vector is exhausted
            }
         }
      }
      if(b == 8) {  // out[i] is filled in
         i++;
      }
   }
}

FrodoSerializedMatrix FrodoMatrix::serialize() const {
   FrodoSerializedMatrix out(2 * m_elements.size());

   for(unsigned int i = 0; i < m_elements.size(); ++i) {
      store_le(m_elements.at(i), out.data() + 2 * i);
   }

   return out;
}

FrodoPlaintext FrodoMatrix::decode(const FrodoKEMConstants& constants) const {
   const size_t nwords = (constants.n_bar() * constants.n_bar()) / 8;
   const uint16_t maskex = static_cast<uint16_t>(1 << constants.b()) - 1;
   const uint16_t maskq = static_cast<uint16_t>(1 << constants.d()) - 1;

   FrodoPlaintext out(nwords * constants.b());

   size_t index = 0;
   for(size_t i = 0; i < nwords; i++) {
      uint64_t templong = 0;
      for(size_t j = 0; j < 8; j++) {
         const auto temp =
            static_cast<uint16_t>(((m_elements.at(index) & maskq) + (1 << (constants.d() - constants.b() - 1))) >>
                                  (constants.d() - constants.b()));
         templong |= static_cast<uint64_t>(temp & maskex) << (constants.b() * j);
         index++;
      }
      for(size_t j = 0; j < constants.b(); j++) {
         out[i * constants.b() + j] = (templong >> (8 * j)) & 0xFF;
      }
   }

   return out;
}

FrodoMatrix FrodoMatrix::unpack(const FrodoKEMConstants& constants,
                                const Dimensions& dimensions,
                                StrongSpan<const FrodoPackedMatrix> packed_bytes) {
   const uint8_t lsb = static_cast<uint8_t>(constants.d());
   const size_t inlen = packed_bytes.size();
   const size_t outlen = static_cast<size_t>(std::get<0>(dimensions)) * std::get<1>(dimensions);

   BOTAN_ASSERT_NOMSG(inlen == ceil_tobytes(outlen * lsb));

   auto elements = make_elements_vector(dimensions);

   size_t i = 0;      // whole uint16_t already filled in
   size_t j = 0;      // whole bytes already copied
   uint8_t w = 0;     // the leftover, not yet copied
   uint8_t bits = 0;  // the number of lsb bits of w

   while(i < outlen && (j < inlen || ((j == inlen) && (bits > 0)))) {
      /*
      in: |  |  |  |  |  |  |**|**|...
                            ^
                            j
      w : | *|
            ^
            bits
      out:|   *****|   *****|   ***  |        |...
                            ^   ^
                            i   b
      */
      uint8_t b = 0;  // bits in out[i] already filled in
      while(b < lsb) {
         const uint8_t nbits = std::min(static_cast<uint8_t>(lsb - b), bits);
         const uint16_t mask = static_cast<uint16_t>(1 << nbits) - 1;
         const uint8_t t = (w >> (bits - nbits)) & mask;  // the bits to copy from w to out

         elements.at(i) = elements.at(i) + static_cast<uint16_t>(t << (lsb - b - nbits));
         b += nbits;
         bits -= nbits;
         w &= static_cast<uint8_t>(~(mask << bits));  // not strictly necessary; mostly for debugging

         if(bits == 0) {
            if(j < inlen) {
               w = packed_bytes[j];
               bits = 8;
               j++;
            } else {
               break;  // the input vector is exhausted
            }
         }
      }
      if(b == lsb) {  // out[i] is filled in
         i++;
      }
   }

   return FrodoMatrix(dimensions, std::move(elements));
}

FrodoMatrix FrodoMatrix::deserialize(const Dimensions& dimensions, StrongSpan<const FrodoSerializedMatrix> bytes) {
   auto elements = make_elements_vector(dimensions);
   BOTAN_ASSERT_NOMSG(elements.size() * 2 == bytes.size());
   load_le<uint16_t>(elements.data(), bytes.data(), elements.size());
   return FrodoMatrix(dimensions, std::move(elements));
}

void FrodoMatrix::reduce(const FrodoKEMConstants& constants) {
   // Reduction is inherent if D is 16, because we use uint16_t in m_elements
   if(constants.d() < sizeof(decltype(m_elements)::value_type) * 8) {
      const uint16_t mask = static_cast<uint16_t>(1 << constants.d()) - 1;
      for(auto& elem : m_elements) {
         elem = elem & mask;  // mod q
      }
   }
}

}  // namespace Botan
