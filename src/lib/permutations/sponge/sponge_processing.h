/*
* Byte-oriented Sponge processing helpers
* (C) 2025 Jack Lloyd
*     2025 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SPONGE_PROCESSING_H_
#define BOTAN_SPONGE_PROCESSING_H_

#include <botan/exceptn.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
#include <array>
#include <span>

namespace Botan {

namespace detail {

template <typename T>
concept SpongeLike = std::unsigned_integral<decltype(T::word_bytes)> && requires(T a) {
   typename T::word_t;
   typename T::state_t;
   { a.state() } -> std::same_as<typename T::state_t&>;
   { a._cursor() } -> std::same_as<size_t&>;
   { a.byte_rate() } -> std::same_as<size_t>;
};

template <typename T>
concept SpongeLikeWithTrivialPermute = SpongeLike<T> && requires(T a) {
   { a.permute() } -> std::same_as<void>;
};

/**
* Represents the bounds of partial byte-oriented data within a word of
* the sponge state. Downstream algorithms can use this to conveniently
* modify the passed in partial state word with data written or read
* from an input or output byte buffer.
*/
template <SpongeLike SpongeT>
class PartialWordBounds final {
   public:
      size_t offset;  // NOLINT(*-non-private-member-*)
      size_t length;  // NOLINT(*-non-private-member-*)

   private:
      using word_t = typename SpongeT::word_t;
      constexpr static auto word_bytes = SpongeT::word_bytes;

   public:
      /**
      * Reads '.length' bytes from the provided slicer and places them
      * within a word at the specified '.offset' in little-endian order.
      */
      word_t read_from(BufferSlicer& slicer) const {
         std::array<uint8_t, word_bytes> partial_word_bytes{};
         slicer.copy_into(std::span{partial_word_bytes}.subspan(offset, length));
         return load_le(partial_word_bytes);
      }

      /**
      * Writes '.length' bytes from the provided word at the specified
      * '.offset' into the provided stuffer in little-endian order.
      */
      void write_into(BufferStuffer& stuffer, word_t partial_word) const {
         const auto partial_word_bytes = store_le(partial_word);
         stuffer.append(std::span{partial_word_bytes}.subspan(offset, length));
      }

      /**
      * Assigns the bits in 'partial_input_word' to their corresponding
      * bits in 'state_word' at the specified '.offset' and '.length'
      * while leaving all other bits in 'state_word' unchanged.
      */
      word_t masked_assignment(word_t state_word, word_t partial_input_word) const {
         const auto mask = ((word_t(0) - 1) >> ((word_bytes - length) * 8)) << (offset * 8);
         return (state_word & ~mask) | (partial_input_word & mask);
      }
};

/**
* A drop-in replacement for `PartialWordBounds` that is optimized for
* handling full words where no masking or offsetting is necessary.
*/
template <SpongeLike SpongeT>
class FullWordBounds final {
   private:
      using word_t = typename SpongeT::word_t;
      constexpr static auto word_bytes = SpongeT::word_bytes;

   public:
      word_t read_from(BufferSlicer& slicer) const { return load_le(slicer.take<word_bytes>()); }

      void write_into(BufferStuffer& stuffer, word_t full_word) const { stuffer.append(store_le(full_word)); }

      word_t masked_assignment(word_t, word_t full_input_word) const { return full_input_word; }
};

template <typename T>
concept PermutationFn = std::invocable<T> || std::same_as<T, void()>;

template <typename T, typename SpongeT, typename ModifierT>
concept BaseModifierFn = requires(T fn, typename SpongeT::word_t word, ModifierT bounds) {
   { std::invoke(fn, word, bounds) } -> std::same_as<typename SpongeT::word_t>;
};

template <typename T, typename SpongeT>
concept ModifierFn =
   BaseModifierFn<T, SpongeT, FullWordBounds<SpongeT>> || BaseModifierFn<T, SpongeT, PartialWordBounds<SpongeT>>;

}  // namespace detail

/**
* Performs the core processing loop for ingesting or extracting data into/from
* the sponge state in a byte-oriented manner for the given number of
* @p bytes_to_process. The provided @p word_modifier_fn is called for each
* (partial) word of the sponge state that needs to be modified or read.
*
* The processing loop ensures efficient handling of unaligned input and output
* data. For that, it calls the provided permutation function either with an
* instance of `PartialWordBounds` or `FullWordBounds`. Hence @p word_modifier_fn
* must be able to handle both types of bounds and should use their respective
* methods to read from or write into input or output buffers.
*
* @param sponge the sponge instance to process data into or from
* @param bytes_to_process the number of sponge state bytes to traverse
* @param permutation_fn a function that performs the sponge's permutation
* @param modifier_fn a function that modifies the sponge state words
*/
template <detail::SpongeLike SpongeT>
BOTAN_FORCE_INLINE void process_bytes_in_sponge(SpongeT& sponge,
                                                size_t bytes_to_process,
                                                const detail::PermutationFn auto& permutation_fn,
                                                const detail::ModifierFn<SpongeT> auto& modifier_fn) {
   constexpr auto word_bytes = SpongeT::word_bytes;
   const auto byte_rate = sponge.byte_rate();
   auto& S = sponge.state();
   auto& cursor = sponge._cursor();

   // If necessary, try to get aligned with the sponge state's words array
   const auto bytes_out_of_word_alignment = static_cast<size_t>(cursor % word_bytes);
   if(bytes_out_of_word_alignment > 0) {
      const auto bytes_until_word_alignment = word_bytes - bytes_out_of_word_alignment;
      const auto bytes_from_input = std::min(bytes_to_process, bytes_until_word_alignment);
      BOTAN_DEBUG_ASSERT(bytes_from_input < word_bytes);

      S[cursor / word_bytes] = modifier_fn(S[cursor / word_bytes],
                                           detail::PartialWordBounds<SpongeT>{
                                              .offset = bytes_out_of_word_alignment,
                                              .length = bytes_from_input,
                                           });
      cursor += bytes_from_input;
      bytes_to_process -= bytes_from_input;

      if(cursor == byte_rate) {
         permutation_fn();
         cursor = 0;
      }
   }

   // If we didn't exhaust the bytes to process for this invocation, we should
   // be word-aligned with the sponge state now
   BOTAN_DEBUG_ASSERT(bytes_to_process == 0 || cursor % word_bytes == 0);

   // Block-wise incorporation of the input data into the sponge state until
   // all input bytes are processed
   while(bytes_to_process >= word_bytes) {
      // Process full words until we either run out of data or reach the
      // end of the current sponge state block
      while(bytes_to_process >= word_bytes && cursor < byte_rate) {
         S[cursor / word_bytes] = modifier_fn(S[cursor / word_bytes], detail::FullWordBounds<SpongeT>{});
         cursor += word_bytes;
         bytes_to_process -= word_bytes;
      }

      if(cursor == byte_rate) {
         permutation_fn();
         cursor = 0;
      }
   }

   // Process the remaining bytes that don't fill an entire word.
   // Therefore, leaving the sponge state in an unaligned state that won't
   // need another permutation until the next call to process().
   BOTAN_DEBUG_ASSERT(bytes_to_process < word_bytes && cursor < byte_rate);
   if(bytes_to_process > 0) {
      S[cursor / word_bytes] = modifier_fn(S[cursor / word_bytes],
                                           detail::PartialWordBounds<SpongeT>{
                                              .offset = 0,
                                              .length = bytes_to_process,
                                           });
      cursor += bytes_to_process;
   }
}

template <detail::SpongeLikeWithTrivialPermute SpongeT>
inline void process_bytes_in_sponge(SpongeT& sponge,
                                    size_t bytes_to_process,
                                    const detail::ModifierFn<SpongeT> auto& modifier_fn) {
   process_bytes_in_sponge(
      sponge, bytes_to_process, [&sponge] { sponge.permute(); }, modifier_fn);
}

/**
* Absorbs @p input data into the @p sponge state.
*
* @param sponge The sponge state to absorb data into.
* @param input The input data to absorb.
* @param permutation_fn The function to call for the sponge's permutation.
*/
template <detail::SpongeLike SpongeT>
inline void absorb_into_sponge(SpongeT& sponge,
                               std::span<const uint8_t> input,
                               const detail::PermutationFn auto& permutation_fn) {
   using word_t = typename SpongeT::word_t;

   BufferSlicer input_slicer(input);
   process_bytes_in_sponge(sponge, input.size(), permutation_fn, [&](word_t state_word, auto bounds) {
      return state_word ^ bounds.read_from(input_slicer);
   });
   BOTAN_ASSERT_NOMSG(input_slicer.empty());
}

inline void absorb_into_sponge(detail::SpongeLikeWithTrivialPermute auto& sponge, std::span<const uint8_t> input) {
   absorb_into_sponge(sponge, input, [&sponge] { sponge.permute(); });
}

/**
* Squeezes @p output data from the @p sponge state.
*
* @param sponge The sponge state to squeeze data from.
* @param output The output buffer to write the squeezed data into.
* @param permutation_fn The function to call for the sponge's permutation.
*/
template <detail::SpongeLike SpongeT>
inline void squeeze_from_sponge(SpongeT& sponge,
                                std::span<uint8_t> output,
                                const detail::PermutationFn auto& permutation_fn) {
   using word_t = typename SpongeT::word_t;

   BufferStuffer output_stuffer(output);
   process_bytes_in_sponge(sponge, output.size(), permutation_fn, [&](word_t state_word, auto bounds) {
      bounds.write_into(output_stuffer, state_word);
      return state_word;
   });
   BOTAN_ASSERT_NOMSG(output_stuffer.full());
}

inline void squeeze_from_sponge(detail::SpongeLikeWithTrivialPermute auto& sponge, std::span<uint8_t> output) {
   squeeze_from_sponge(sponge, output, [&sponge] { sponge.permute(); });
}

}  // namespace Botan

#endif
