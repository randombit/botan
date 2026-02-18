/*
* (C) 2026 Jack Lloyd
*     2026 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EC_SEC1_H_
#define BOTAN_EC_SEC1_H_

#include <botan/concepts.h>
#include <botan/internal/ct_utils.h>
#include <optional>
#include <span>

namespace Botan {

struct SEC1_Identity {
      constexpr static uint8_t label = 0x00;
};

struct SEC1_Compressed {
      constexpr static uint8_t even_label = 0x02;
      constexpr static uint8_t odd_label = 0x03;

      CT::Choice y_is_even;
      std::span<const uint8_t> x;
};

struct SEC1_Full {
      constexpr static uint8_t label = 0x04;
      constexpr static uint8_t even_hybrid_label = 0x06;
      constexpr static uint8_t odd_hybrid_label = 0x07;

      std::span<const uint8_t> x;
      std::span<const uint8_t> y;
};

namespace detail {

template <typename R>
struct unwrap_optional {
      using type = R;
};

template <typename T>
struct unwrap_optional<std::optional<T>> {
      using type = T;
};

template <typename R>
using unwrap_optional_t = typename unwrap_optional<R>::type;

template <typename FnT>
concept sec1_decode_handler =
   std::invocable<FnT, SEC1_Identity> && std::invocable<FnT, SEC1_Compressed> && std::invocable<FnT, SEC1_Full> &&
   all_same_v<unwrap_optional_t<std::invoke_result_t<FnT, SEC1_Identity>>,
              unwrap_optional_t<std::invoke_result_t<FnT, SEC1_Compressed>>,
              unwrap_optional_t<std::invoke_result_t<FnT, SEC1_Full>>>;

template <sec1_decode_handler FnT>
using sec1_decode_result_t = unwrap_optional_t<std::invoke_result_t<FnT, SEC1_Identity>>;

}  // namespace detail

/**
 * Decode a SEC1-encoded point and pass the decoded values to @p handler.
 * The handler must be a function that is prepared to take any of SEC1_Identity,
 * SEC1_Compressed, or SEC1_Full and returns either a consistent type or said
 * type wrapped into a std::optional. The handler may either throw or return
 * an empty std::optional to indicate that it failed handling the passed values.
 *
 * Note that the referenced bytes in the SEC1_Compressed and SEC1_Full structs
 * are not guaranteed to be valid after the function returns. When you need them
 * outside the scope of @p handler, you need to copy them.
 *
 * @param bytes the SEC1-encoded bytes to decode
 * @param field_element_bytes number of bytes in a field element of the curve
 * @param handler the handler to call with the decoded values
 * @return the return value of the handler or an empty std::optional if the
 *         handler failed to handle the passed values
 */
template <typename FnT>
constexpr std::optional<detail::sec1_decode_result_t<FnT>> sec1_decode(std::span<const uint8_t> bytes,
                                                                       size_t field_element_bytes,
                                                                       FnT handler) {
   if(bytes.empty()) {
      return {};
   }

   // The first byte is the distinctive header
   const auto hdr = bytes[0];

   // Identity point (single byte 0x00)
   if(bytes.size() == 1 && hdr == SEC1_Identity::label) {
      return handler(SEC1_Identity{});
   }

   // Compressed point (0x02|0x03 || x)
   if(bytes.size() == 1 + field_element_bytes &&
      (hdr == SEC1_Compressed::even_label || hdr == SEC1_Compressed::odd_label)) {
      return handler(SEC1_Compressed{
         .y_is_even = CT::Mask<uint8_t>::is_equal(hdr, SEC1_Compressed::even_label).as_choice(),
         .x = bytes.subspan(1, field_element_bytes),
      });
   }

   // Uncompressed point (0x04 || x || y)
   // or deprecated hybrid point (0x06|0x07 || x || y)
   if(bytes.size() == 1 + 2 * field_element_bytes) {
      const SEC1_Full full = {
         .x = bytes.subspan(1, field_element_bytes),
         .y = bytes.subspan(1 + field_element_bytes, field_element_bytes),
      };

      // The deprecated "hybrid" point format
      // TODO(Botan4): remove this
      if(hdr == SEC1_Full::even_hybrid_label || hdr == SEC1_Full::odd_hybrid_label) {
         const auto hdr_is_odd = CT::Mask<uint8_t>::is_equal(hdr, SEC1_Full::odd_hybrid_label).as_choice();
         const auto y_is_odd = CT::Mask<uint8_t>::expand_bit(full.y.back(), 0).as_choice();

         if((hdr_is_odd != y_is_odd).as_bool()) {
            return {};  // invalid parity in hybrid format
         }
      } else if(hdr != SEC1_Full::label) {
         return {};  // invalid label
      }

      return handler(full);
   }

   // Some non-empty invalid input
   return {};
}

}  // namespace Botan

#endif
