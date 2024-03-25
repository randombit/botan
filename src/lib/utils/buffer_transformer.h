/*
 * Buffer Transformer
 * (C) 2024 Jack Lloyd
 *     2024 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_BUFFER_TRANSFORMER_H_
#define BOTAN_BUFFER_TRANSFORMER_H_

#include <botan/internal/stl_util.h>

namespace Botan {

/**
 * @brief Helper class combining the BufferStuffer and BufferSlicer
 *
 * Use this class to transform data from one buffer to another in a streaming
 * fashion. The input and output buffers must be of the same size.
 */
class BufferTransformer {
   public:
      template <size_t count = std::dynamic_extent>
      using ispan = std::span<const uint8_t, count>;

      template <size_t count = std::dynamic_extent>
      using ospan = std::span<uint8_t, count>;

   public:
      BufferTransformer(ispan<> in, ospan<> out) : m_in(in), m_out(out) {
         BOTAN_ARG_CHECK(in.size() == out.size(), "Input and output buffers must be the same size");
      }

      std::pair<ispan<>, ospan<>> next(size_t count) { return {m_in.take(count), m_out.next(count)}; }

      template <size_t count>
      std::pair<ispan<count>, ospan<count>> next() {
         return {m_in.take<count>(), m_out.next<count>()};
      }

      void skip(const size_t count) { next(count); }

      size_t remaining() const {
         BOTAN_DEBUG_ASSERT(m_in.remaining() == m_out.remaining_capacity());
         return m_in.remaining();
      }

      bool done() const {
         BOTAN_DEBUG_ASSERT(m_in.empty() == m_out.full());
         return m_in.empty();
      }

   private:
      BufferSlicer m_in;
      BufferStuffer m_out;
};

}  // namespace Botan

#endif
