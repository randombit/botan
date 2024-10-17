/*
 * PQ CRYSTALS Encoding Helpers
 *
 * Further changes
 * (C) 2024 Jack Lloyd
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_PQ_CRYSTALS_ENCODING_H_
#define BOTAN_PQ_CRYSTALS_ENCODING_H_

#include <limits>
#include <numeric>
#include <span>

#include <botan/internal/loadstor.h>
#include <botan/internal/pqcrystals.h>
#include <botan/internal/pqcrystals_helpers.h>
#include <botan/internal/stl_util.h>

#if defined(BOTAN_HAS_XOF)
   #include <botan/xof.h>
#endif
namespace Botan::CRYSTALS {

namespace detail {

constexpr auto as_byte_source(BufferSlicer& slicer) {
   return [&](std::span<uint8_t> out) { slicer.copy_into(out); };
}

#if defined(BOTAN_HAS_XOF)
constexpr auto as_byte_source(Botan::XOF& xof) {
   return [&](std::span<uint8_t> out) { xof.output(out); };
}
#endif

}  // namespace detail

template <typename T>
concept byte_source =
   requires(T& t) { requires std::invocable<decltype(detail::as_byte_source(t)), std::span<uint8_t>>; };

template <typename T, typename PolyCoeffT>
concept coeff_map_fn = std::signed_integral<PolyCoeffT> && requires(T fn, PolyCoeffT coeff) {
   { fn(coeff) } -> std::same_as<std::make_unsigned_t<PolyCoeffT>>;
};

template <typename T, typename PolyCoeffT>
concept coeff_unmap_fn =
   std::signed_integral<PolyCoeffT> && requires(T fn, std::make_unsigned_t<PolyCoeffT> coeff_value) {
      { fn(coeff_value) } -> std::same_as<PolyCoeffT>;
   };

/**
 * Helper for base implementations of NIST FIPS 204, Algorithms 16-19 and
 * NIST FIPS 203 Algorithms 5-6. It pre-computes generic values to bit-(un)pack
 * polynomial coefficients at compile-time.
 *
 * The base implementations are also templated with the @p range parameter
 * forcing the compiler to generate specialized code for each supported range.
 */
template <int32_t range, crystals_trait PolyTrait>
struct BitPackingTrait final {
      using T = typename PolyTrait::T;
      using unsigned_T = std::make_unsigned_t<T>;
      using sink_t = uint64_t;

      static_assert(range <= std::numeric_limits<T>::max());

      constexpr static size_t bits_in_collector = sizeof(sink_t) * 8;
      constexpr static size_t bits_per_coeff = bitlen(range);
      constexpr static size_t bits_per_pack = [] {
         // Ensure that the bit-packing is byte-aligned and scale it
         // to utilize the collector's bit-width as much as possible.
         size_t smallest_aligned_pack = std::lcm(bits_per_coeff, size_t(8));
         return (smallest_aligned_pack < bits_in_collector)
                   ? (bits_in_collector / smallest_aligned_pack) * smallest_aligned_pack
                   : smallest_aligned_pack;
      }();
      constexpr static size_t bytes_per_pack = bits_per_pack / 8;
      constexpr static size_t coeffs_per_pack = bits_per_pack / bits_per_coeff;
      constexpr static size_t collectors_per_pack = (bytes_per_pack + sizeof(sink_t) - 1) / sizeof(sink_t);
      constexpr static size_t collector_bytes_per_pack = collectors_per_pack * sizeof(sink_t);
      constexpr static sink_t value_mask = (1 << bits_per_coeff) - 1;

      using collector_array = std::array<sink_t, collectors_per_pack>;
      using collector_bytearray = std::array<uint8_t, collector_bytes_per_pack>;

      static_assert(PolyTrait::N % coeffs_per_pack == 0);
};

/**
 * Base implementation of NIST FIPS 203 Algorithm 5 (ByteEncode) and NIST
 * FIPS 204 Algorithms 16 (SimpleBitPack) and 17 (BitPack).
 *
 * This takes a polynomial @p p and packs its coefficients into the buffer
 * represented by @p stuffer. Optionally, the coefficients can be transformed
 * using the @p map function before packing them. Kyber uses @p map to compress
 * the coefficients as needed, Dilithium to transform coefficients to unsigned.
 *
 * The implementation assumes that the values returned from the custom @p map
 * transformation are in the range [0, range]. No assumption is made about the
 * value range of the coefficients in the polynomial @p p.
 *
 * Note that this bit-packing algorithm is inefficient if the bit-length of the
 * coefficients is a multiple of 8. In that case, a byte-level encoding (that
 * might need to take endianess into account) would be more efficient. However,
 * neither Kyber nor Dilithium instantiate bit-packings with such a value range.
 *
 * @tparam range the upper bound of the coefficient range.
 */
template <int32_t range, crystals_trait PolyTrait, Domain D, coeff_map_fn<typename PolyTrait::T> MapFnT>
constexpr void pack(const Polynomial<PolyTrait, D>& p, BufferStuffer& stuffer, MapFnT map) {
   using trait = BitPackingTrait<range, PolyTrait>;

   BOTAN_DEBUG_ASSERT(stuffer.remaining_capacity() >= p.size() * trait::bits_per_coeff / 8);

   // Bit-packing example that shows a coefficients' bit-pack that spills across
   // more than one 64-bit collectors. This illustrates the algorithm below.
   //
   //                         0                                       64                                       128
   // Collectors   (64 bits): |               collectors[0]            |               collectors[1]            |
   //                         |                                        |                                        |
   // Coefficients (11 bits): | c[0] | c[1] | c[2] | c[3] | c[4] | c[5] | c[6] | c[7] |      |      |      |      | ...
   //                         |                                                       |                         |
   //                         |         < byte-aligned coefficient pack >             |  < byte-aligned pad. >  |
   //                         |             (one inner loop iteration)                |
   //                         0                                                      88 (divisible by 8)

   for(size_t i = 0; i < p.size(); i += trait::coeffs_per_pack) {
      // The collectors array is filled with bit-packed coefficients to produce
      // a byte-aligned pack of coefficients. When coefficients fall onto the
      // boundary of two collectors, their bits must be split.
      typename trait::collector_array collectors = {0};
      for(size_t j = 0, bit_offset = 0, c = 0; j < trait::coeffs_per_pack; ++j) {
         // Transform p[i] via a custom map function (that may be a NOOP).
         const typename trait::unsigned_T mapped_coeff = map(p[i + j]);
         const auto coeff_value = static_cast<typename trait::sink_t>(mapped_coeff);

         // pack() is called only on data produced by us. If the values returned
         // by the map function are not in the range [0, range] we have a bug.
         BOTAN_DEBUG_ASSERT(coeff_value <= range);

         // Bit-pack the coefficient into the collectors array and keep track of
         // the bit-offset within the current collector. Note that this might
         // shift some high-bits of the coefficient out of the current collector.
         collectors[c] |= coeff_value << bit_offset;
         bit_offset += trait::bits_per_coeff;

         // If the bit-offset now exceeds the collector's bit-width, we fill the
         // next collector with the high-bits that didn't fit into the previous.
         // The bit-offset is adjusted to now point into the new collector.
         if(bit_offset > trait::bits_in_collector) {
            bit_offset = bit_offset - trait::bits_in_collector;
            collectors[++c] = coeff_value >> (trait::bits_per_coeff - bit_offset);
         }
      }

      // One byte-aligned pack of bit-packed coefficients is now stored in the
      // collectors and can be written to an output buffer. Note that we might
      // have to remove some padding bytes of unused collector space.
      const auto bytes = store_le(collectors);
      stuffer.append(std::span{bytes}.template first<trait::bytes_per_pack>());
   }
}

/**
 * Base implementation of NIST FIPS 203 Algorithm 6 (ByteDecode) and NIST
 * FIPS 204 Algorithms 18 (SimpleBitUnpack) and 19 (BitUnpack).
 *
 * This takes a byte sequence represented by @p byte_source and unpacks its
 * coefficients into the polynomial @p p. Optionally, the coefficients can be
 * transformed using the @p unmap function after unpacking them. Note that
 * the @p unmap function must be able to deal with out-of-range values, as the
 * input to `unpack()` may be untrusted data.
 *
 * Kyber uses @p unmap to decompress the coefficients as needed, Dilithium uses
 * it to convert the coefficients back to signed integers.
 *
 * @tparam range the upper bound of the coefficient range.
 */
template <int32_t range,
          byte_source ByteSourceT,
          crystals_trait PolyTrait,
          Domain D,
          coeff_unmap_fn<typename PolyTrait::T> UnmapFnT>
constexpr void unpack(Polynomial<PolyTrait, D>& p, ByteSourceT& byte_source, UnmapFnT unmap) {
   using trait = BitPackingTrait<range, PolyTrait>;

   auto get_bytes = detail::as_byte_source(byte_source);
   typename trait::collector_bytearray bytes = {0};

   // This is the inverse operation of the bit-packing algorithm above. Please
   // refer to the comments there for a detailed explanation of the algorithm.
   for(size_t i = 0; i < p.size(); i += trait::coeffs_per_pack) {
      get_bytes(std::span{bytes}.template first<trait::bytes_per_pack>());
      const auto collectors = load_le<typename trait::collector_array>(bytes);

      for(size_t j = 0, bit_offset = 0, c = 0; j < trait::coeffs_per_pack; ++j) {
         typename trait::sink_t coeff_value = collectors[c] >> bit_offset;
         bit_offset += trait::bits_per_coeff;
         if(bit_offset > trait::bits_in_collector) {
            bit_offset = bit_offset - trait::bits_in_collector;
            coeff_value |= collectors[++c] << (trait::bits_per_coeff - bit_offset);
         }

         // unpack() may be called on data produced by an untrusted party.
         // The values passed into the unmap function may be out of range, hence
         // it is acceptable for unmap to return an out-of-range value then.
         //
         // For that reason we cannot use BOTAN_ASSERT[_DEBUG] on the values.
         p[i + j] = unmap(static_cast<typename trait::unsigned_T>(coeff_value & trait::value_mask));
      }
   }
}

/// Overload for packing polynomials with a NOOP map function
template <int32_t range, crystals_trait PolyTrait, Domain D>
constexpr void pack(const Polynomial<PolyTrait, D>& p, BufferStuffer& stuffer) {
   using unsigned_T = std::make_unsigned_t<typename PolyTrait::T>;
   pack<range>(p, stuffer, [](typename PolyTrait::T x) { return static_cast<unsigned_T>(x); });
}

/// Overload for unpacking polynomials with a NOOP unmap function
template <int32_t range, byte_source ByteSourceT, crystals_trait PolyTrait, Domain D>
constexpr void unpack(Polynomial<PolyTrait, D>& p, ByteSourceT& byte_source) {
   using unsigned_T = std::make_unsigned_t<typename PolyTrait::T>;
   unpack<range>(p, byte_source, [](unsigned_T x) { return static_cast<typename PolyTrait::T>(x); });
}

}  // namespace Botan::CRYSTALS

#endif
