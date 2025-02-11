/*
 * Buffer Transformer
 * (C) 2024 Jack Lloyd
 *     2024 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_BUFFER_TRANSFORMER_H_
#define BOTAN_BUFFER_TRANSFORMER_H_

#include <botan/concepts.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace detail {

template <size_t count = std::dynamic_extent>
using ispan = std::span<const uint8_t, count>;

template <size_t count = std::dynamic_extent>
using ospan = std::span<uint8_t, count>;

template <typename FnT, size_t... block_sizes>
concept block_processing_callback = (std::invocable<FnT, ispan<block_sizes>, ospan<block_sizes>> && ...);

template <size_t = 0>
consteval bool is_strictly_monotonic_decreasing() {
   return true;
}

template <size_t biggest, size_t bigger, size_t... smaller>
consteval bool is_strictly_monotonic_decreasing() {
   return (biggest > bigger) && is_strictly_monotonic_decreasing<bigger, smaller...>();
}

/**
 * Ensures that the sequence of block_sizes is strictly becoming smaller
 * A sequence of length 1 or the empty sequence satisfy this by definition.
 */
template <size_t... block_sizes>
concept strictly_monotonic_decreasing = is_strictly_monotonic_decreasing<block_sizes...>();

}  // namespace detail

/**
 * @brief Process data from an input buffer into an output buffer
 *
 * Use this class to transform data from one buffer to another in a streaming
 * fashion. The input and output buffers must be of the same size.
 */
class BufferTransformer {
   public:
      template <ranges::spanable_range InT, ranges::spanable_range OutT>
         requires(std::same_as<std::ranges::range_value_t<InT>, uint8_t> &&
                  std::same_as<std::ranges::range_value_t<OutT>, uint8_t>)
      BufferTransformer(InT&& in, OutT&& out) :
            m_in(detail::ispan<>(in)), m_out(detail::ospan<>(out)), m_block_processing(false) {
         ranges::assert_equal_byte_lengths(in, out);
      }

      /**
       * @returns a pair of input and output spans of the given byte @p count
       */
      std::pair<detail::ispan<>, detail::ospan<>> next(size_t count) {
         BOTAN_STATE_CHECK(!m_block_processing);
         return {m_in.take(count), m_out.next(count)};
      }

      /**
       * @returns a pair of input and output spans with static extent
       */
      template <size_t count>
      std::pair<detail::ispan<count>, detail::ospan<count>> next() {
         BOTAN_STATE_CHECK(!m_block_processing);
         return {m_in.take<count>(), m_out.next<count>()};
      }

      /**
       * Skips the next @p count bytes in both input and output buffers
       */
      void skip(const size_t count) {
         BOTAN_STATE_CHECK(!m_block_processing);
         next(count);
      }

      /**
       * @brief Block-wise processing of the input into the output buffer
       *
       * Specify the desired block size(s) in strictly decreasing order as
       * template parameter(s). This will process the input buffer in the
       * largest possible block size and fall back to smaller ones as necessary.
       *
       * The provided callback @p fn is expected to be a callable object that
       * accepts input/output spans of all given block sizes. Typically this is
       * done with the `overloaded{}` helper or a generic lambda. E.g.
       *
       * @code
       *   transformer.process_blocks_of<64, 32, 16>(overloaded{
       *     [](std::span<const uint8_t, 64>, std::span<uint8_t, 64>) { ... },
       *     [](std::span<const uint8_t, 32>, std::span<uint8_t, 32>) { ... },
       *     [](std::span<const uint8_t, 16>, std::span<uint8_t, 16>) { ... }});
       *
       *   transformer.process_blocks_of<64, 32, 16>([](auto in, auto out) {
       *     if constexpr(in.size() == 64) { ... }
       *     else if constexpr(in.size() == 32) { ... }
       *     else if constexpr(in.size() == 16) { ... }
       *   });
       * @endcode
       *
       * @note This will always transform the entire buffer. Consuming data via
       *       any other method is prohibited once block processing has started.
       */
      template <size_t... block_sizes>
         requires(sizeof...(block_sizes) > 0) && (detail::strictly_monotonic_decreasing<block_sizes...>)
      void process_blocks_of(detail::block_processing_callback<block_sizes...> auto&& fn) {
         BOTAN_STATE_CHECK(!m_block_processing);
         m_block_processing = true;

         constexpr size_t smallest_block_size = std::min({block_sizes...});
         // If there is a 1-byte block size, we can trivially process any byte
         // range, else we validate that the range will be fully processible by
         // the given sequence of block sizes.
         if constexpr(smallest_block_size > 1) {
            size_t bytes_to_process = remaining();
            ([&](size_t block_size) { bytes_to_process = bytes_to_process % block_size; }(block_sizes), ...);
            BOTAN_ARG_CHECK(bytes_to_process == 0, "Input size cannot be block-processed");
         }

         // Process the range in blocks of the given sizes, falling back to
         // the smaller blocks as needed.
         (opportunistically_process_blocks_of<block_sizes>(fn), ...);

         BOTAN_DEBUG_ASSERT(done());
      }

      size_t remaining() const {
         BOTAN_DEBUG_ASSERT(m_in.remaining() == m_out.remaining_capacity());
         return m_in.remaining();
      }

      bool done() const {
         BOTAN_DEBUG_ASSERT(m_in.empty() == m_out.full());
         return m_in.empty();
      }

   private:
      /**
       * @brief Process as many blocks of the given size as possible
       */
      template <size_t block_size>
      void opportunistically_process_blocks_of(detail::block_processing_callback<block_size> auto& fn) {
         BOTAN_DEBUG_ASSERT(m_block_processing);
         while(remaining() >= block_size) {
            fn(m_in.take<block_size>(), m_out.next<block_size>());
         }
      }

   private:
      BufferSlicer m_in;
      BufferStuffer m_out;
      bool m_block_processing = false;
};

}  // namespace Botan

#endif
