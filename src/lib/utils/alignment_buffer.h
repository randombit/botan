/*
 * Alignment buffer helper
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_ALIGNMENT_BUFFER_H_
#define BOTAN_ALIGNMENT_BUFFER_H_

#include <botan/concepts.h>
#include <botan/mem_ops.h>
#include <botan/internal/stl_util.h>

#include <array>
#include <optional>
#include <span>

namespace Botan {

/**
 * Defines the strategy for handling the final block of input data in the
 * handle_unaligned_data() method of the AlignmentBuffer<>.
 *
 * - is_not_special:   the final block is treated like any other block
 * - must_be_deferred: the final block is not emitted while bulk processing (typically add_data())
 *                     but is deferred until manually consumed (typically final_result())
 *
 * The AlignmentBuffer<> assumes data to be "the final block" if no further
 * input data is available in the BufferSlicer<>. This might result in some
 * performance overhead when using the must_be_deferred strategy.
 */
enum class AlignmentBufferFinalBlock : size_t {
   is_not_special = 0,
   must_be_deferred = 1,
};

/**
 * @brief Alignment buffer helper
 *
 * Many algorithms have an intrinsic block size in which they consume input
 * data. When streaming arbitrary data chunks to such algorithms we must store
 * some data intermittently to honor the algorithm's alignment requirements.
 *
 * This helper encapsulates such an alignment buffer. The API of this class is
 * designed to minimize user errors in the algorithm implementations. Therefore,
 * it is strongly opinionated on its use case. Don't try to use it for anything
 * but the described circumstance.
 *
 * @tparam T                     the element type of the internal buffer
 * @tparam BLOCK_SIZE            the buffer size to use for the alignment buffer
 * @tparam FINAL_BLOCK_STRATEGY  defines whether the final input data block is
 *                               retained in handle_unaligned_data() and must be
 *                               manually consumed
 */
template <typename T,
          size_t BLOCK_SIZE,
          AlignmentBufferFinalBlock FINAL_BLOCK_STRATEGY = AlignmentBufferFinalBlock::is_not_special>
   requires(BLOCK_SIZE > 0)
class AlignmentBuffer {
   public:
      AlignmentBuffer() : m_position(0) {}

      ~AlignmentBuffer() { secure_scrub_memory(m_buffer.data(), m_buffer.size()); }

      AlignmentBuffer(const AlignmentBuffer& other) = default;
      AlignmentBuffer(AlignmentBuffer&& other) noexcept = default;
      AlignmentBuffer& operator=(const AlignmentBuffer& other) = default;
      AlignmentBuffer& operator=(AlignmentBuffer&& other) noexcept = default;

      void clear() {
         clear_mem(m_buffer.data(), m_buffer.size());
         m_position = 0;
      }

      /**
       * Fills the currently unused bytes of the buffer with zero bytes
       */
      void fill_up_with_zeros() {
         if(!ready_to_consume()) {
            clear_mem(&m_buffer[m_position], elements_until_alignment());
            m_position = m_buffer.size();
         }
      }

      /**
       * Appends the provided @p elements to the buffer. The user has to make
       * sure that @p elements fits in the remaining capacity of the buffer.
       */
      void append(std::span<const T> elements) {
         BOTAN_ASSERT_NOMSG(elements.size() <= elements_until_alignment());
         std::copy(elements.begin(), elements.end(), m_buffer.begin() + m_position);
         m_position += elements.size();
      }

      /**
       * Allows direct modification of the first @p elements in the buffer.
       * This is a low-level accessor that neither takes the buffer's current
       * capacity into account nor does it change the internal cursor.
       * Beware not to overwrite unconsumed bytes.
       */
      std::span<T> directly_modify_first(size_t elements) {
         BOTAN_ASSERT_NOMSG(size() >= elements);
         return std::span(m_buffer).first(elements);
      }

      /**
       * Allows direct modification of the last @p elements in the buffer.
       * This is a low-level accessor that neither takes the buffer's current
       * capacity into account nor does it change the internal cursor.
       * Beware not to overwrite unconsumed bytes.
       */
      std::span<T> directly_modify_last(size_t elements) {
         BOTAN_ASSERT_NOMSG(size() >= elements);
         return std::span(m_buffer).last(elements);
      }

      /**
       * Once the buffer reached alignment, this can be used to consume as many
       * input bytes from the given @p slider as possible. The output always
       * contains data elements that are a multiple of the intrinsic block size.
       *
       * @returns a view onto the aligned data from @p slicer and the number of
       *          full blocks that are represented by this view.
       */
      [[nodiscard]] std::tuple<std::span<const uint8_t>, size_t> aligned_data_to_process(BufferSlicer& slicer) const {
         BOTAN_ASSERT_NOMSG(in_alignment());

         // When the final block is to be deferred, the last block must not be
         // selected for processing if there is no (unaligned) extra input data.
         const size_t defer = (defers_final_block()) ? 1 : 0;
         const size_t full_blocks_to_process = (slicer.remaining() - defer) / m_buffer.size();
         return {slicer.take(full_blocks_to_process * m_buffer.size()), full_blocks_to_process};
      }

      /**
       * Once the buffer reached alignment, this can be used to consume full
       * blocks from the input data represented by @p slicer.
       *
       * @returns a view onto the next full block from @p slicer or std::nullopt
       *          if not enough data is available in @p slicer.
       */
      [[nodiscard]] std::optional<std::span<const uint8_t>> next_aligned_block_to_process(BufferSlicer& slicer) const {
         BOTAN_ASSERT_NOMSG(in_alignment());

         // When the final block is to be deferred, the last block must not be
         // selected for processing if there is no (unaligned) extra input data.
         const size_t defer = (defers_final_block()) ? 1 : 0;
         if(slicer.remaining() < m_buffer.size() + defer) {
            return std::nullopt;
         }

         return slicer.take(m_buffer.size());
      }

      /**
       * Intermittently buffers potentially unaligned data provided in @p
       * slicer. If the internal buffer already contains some elements, data is
       * appended. Once a full block is collected, it is returned to the caller
       * for processing.
       *
       * @param slicer the input data source to be (partially) consumed
       * @returns a view onto a full block once enough data was collected, or
       *          std::nullopt if no full block is available yet
       */
      [[nodiscard]] std::optional<std::span<const T>> handle_unaligned_data(BufferSlicer& slicer) {
         // When the final block is to be deferred, we would need to store and
         // hold a buffer that contains exactly one block until more data is
         // passed or it is explicitly consumed.
         const size_t defer = (defers_final_block()) ? 1 : 0;

         if(in_alignment() && slicer.remaining() >= m_buffer.size() + defer) {
            // We are currently in alignment and the passed-in data source
            // contains enough data to benefit from aligned processing.
            // Therefore, we don't copy anything into the intermittent buffer.
            return std::nullopt;
         }

         // Fill the buffer with as much input data as needed to reach alignment
         // or until the input source is depleted.
         const auto elements_to_consume = std::min(m_buffer.size() - m_position, slicer.remaining());
         append(slicer.take(elements_to_consume));

         // If we collected enough data, we push out one full block. When
         // deferring the final block is enabled, we additionally check that
         // more input data is available to continue processing a consecutive
         // block.
         if(ready_to_consume() && (!defers_final_block() || !slicer.empty())) {
            return consume();
         } else {
            return std::nullopt;
         }
      }

      /**
       * Explicitly consume the currently collected block. It is the caller's
       * responsibility to ensure that the buffer is filled fully. After
       * consumption, the buffer is cleared and ready to collect new data.
       */
      [[nodiscard]] std::span<const T> consume() {
         BOTAN_ASSERT_NOMSG(ready_to_consume());
         m_position = 0;
         return m_buffer;
      }

      /**
       * Explicitly consumes however many bytes are currently stored in the
       * buffer. After consumption, the buffer is cleared and ready to collect
       * new data.
       */
      [[nodiscard]] std::span<const T> consume_partial() {
         const auto elements = elements_in_buffer();
         m_position = 0;
         return std::span(m_buffer).first(elements);
      }

      constexpr size_t size() const { return m_buffer.size(); }

      size_t elements_in_buffer() const { return m_position; }

      size_t elements_until_alignment() const { return m_buffer.size() - m_position; }

      /**
       * @returns true if the buffer is empty (i.e. contains no unaligned data)
       */
      bool in_alignment() const { return m_position == 0; }

      /**
       * @returns true if the buffer is full (i.e. a block is ready to be consumed)
       */
      bool ready_to_consume() const { return m_position == m_buffer.size(); }

      constexpr bool defers_final_block() const {
         return FINAL_BLOCK_STRATEGY == AlignmentBufferFinalBlock::must_be_deferred;
      }

   private:
      std::array<T, BLOCK_SIZE> m_buffer;
      size_t m_position;
};

}  // namespace Botan

#endif
