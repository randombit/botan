/*
* Compression Utils
* (C) 2014,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/compress_utils.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/int_utils.h>
#include <cstdlib>

namespace Botan {

Compression_Error::Compression_Error(const char* func_name, ErrorType type, int rc) :
      Exception(fmt("Compression API {} failed with return code {}", func_name, rc)), m_type(type), m_rc(rc) {}

void* Compression_Alloc_Info::do_malloc(size_t n, size_t size) noexcept {
   // Precheck for integer overflow in the multiplication
   // before passing to calloc, which may or may not check.
   if(!checked_mul(n, size)) {
      return nullptr;
   }

   void* ptr = std::calloc(n, size);  // NOLINT(*-no-malloc,*-owning-memory,*-const-correctness)

   if(ptr == nullptr) {
      return nullptr;
   }

   /*
   * Return null rather than throwing here as we are being called by a
   * C library and it may not be possible for an exception to unwind
   * the call stack from here. The compression library is expecting a
   * function written in C and a null return on error, which it will
   * send upwards to the compression wrappers. So if recording the
   * allocation throws (eg bad_alloc growing the map), free the block and
   * report failure the same way.
   */
   try {
      m_current_allocs[ptr] = n * size;
   } catch(...) {
      std::free(ptr);  // NOLINT(*-no-malloc,*-owning-memory)
      return nullptr;
   }

   return ptr;
}

void Compression_Alloc_Info::do_free(void* ptr) noexcept {
   if(ptr != nullptr) {
      auto i = m_current_allocs.find(ptr);

      if(i == m_current_allocs.end()) {
         /*
         * The compression library tried to free a pointer that was not allocated by
         * a call to the allocation function. We do not have any particularly good
         * options here.
         *
         * - Throwing is not possible since it would unwind through a C ABI library,
         *   which results in undefined behavior.
         *
         * - We could panic (fprintf to stderr and abort) but causing a unilateral
         *   and unrecoverable process crash isn't necessarily the right choice either.
         *
         * - We could skip the scrub step and pass the pointer along directly to
         *   std::free, but that risks corrupting the system heap.
         *
         * So instead we just ignore the request entirely
         */
         return;
      }

      secure_scrub_memory(ptr, i->second);
      std::free(ptr);  // NOLINT(*-no-malloc,*-owning-memory)
      m_current_allocs.erase(i);
   }
}

void Stream_Compression::clear() {
   m_stream.reset();
}

void Stream_Compression::start(size_t level) {
   m_stream = make_stream(level);
}

void Stream_Compression::process(secure_vector<uint8_t>& buf, size_t offset, uint32_t flags) {
   BOTAN_ASSERT(m_stream, "Initialized");
   BOTAN_ASSERT(buf.size() >= offset, "Offset is sane");

   // bzip doesn't like being called with no input and BZ_RUN
   if(buf.size() == offset && flags == m_stream->run_flag()) {
      return;
   }

   const size_t buffer_needed = add_or_throw(buf.size(), offset, "Compression input too large");
   if(m_buffer.size() < buffer_needed) {
      m_buffer.resize(buffer_needed);
   }

   // If the output buffer has zero length, .data() might return nullptr. This would
   // make some compression algorithms (notably those provided by zlib) fail.
   // Any small positive value works fine, but we choose 32 as it is the smallest power
   // of two that is large enough to hold all the headers and trailers of the common
   // formats, preventing further resizings to make room for output data.
   if(m_buffer.empty()) {
      m_buffer.resize(32);
   }

   m_stream->next_in(buf.data() + offset, buf.size() - offset);
   m_stream->next_out(m_buffer.data() + offset, m_buffer.size() - offset);

   while(true) {
      const bool stream_end = m_stream->run(flags);

      if(stream_end) {
         BOTAN_ASSERT(m_stream->avail_in() == 0, "After stream is done, no input remains to be processed");
         m_buffer.resize(m_buffer.size() - m_stream->avail_out());
         break;
      } else if(m_stream->avail_out() == 0) {
         const size_t added = add_or_throw<size_t>(m_buffer.size(), 8, "Compression output too large");
         const size_t new_size = add_or_throw(m_buffer.size(), added, "Compression output too large");
         m_buffer.resize(new_size);
         m_stream->next_out(m_buffer.data() + m_buffer.size() - added, added);
      } else if(m_stream->avail_in() == 0) {
         m_buffer.resize(m_buffer.size() - m_stream->avail_out());
         break;
      }
   }

   copy_mem(m_buffer.data(), buf.data(), offset);
   buf.swap(m_buffer);
}

void Stream_Compression::update(secure_vector<uint8_t>& buf, size_t offset, bool flush) {
   BOTAN_ASSERT(m_stream, "Initialized");
   process(buf, offset, flush ? m_stream->flush_flag() : m_stream->run_flag());
}

void Stream_Compression::finish(secure_vector<uint8_t>& buf, size_t offset) {
   BOTAN_ASSERT(m_stream, "Initialized");
   process(buf, offset, m_stream->finish_flag());
   clear();
}

void Stream_Decompression::clear() {
   m_stream.reset();
}

void Stream_Decompression::start() {
   m_stream = make_stream();
}

void Stream_Decompression::process(secure_vector<uint8_t>& buf, size_t offset, uint32_t flags) {
   BOTAN_ASSERT(m_stream, "Initialized");
   BOTAN_ASSERT(buf.size() >= offset, "Offset is sane");

   const size_t buffer_needed = add_or_throw(buf.size(), offset, "Compression input too large");
   if(m_buffer.size() < buffer_needed) {
      m_buffer.resize(buffer_needed);
   }

   m_stream->next_in(buf.data() + offset, buf.size() - offset);
   m_stream->next_out(m_buffer.data() + offset, m_buffer.size() - offset);

   while(true) {
      const bool stream_end = m_stream->run(flags);

      if(stream_end) {
         if(m_stream->avail_in() == 0) {
            // all data consumed
            m_buffer.resize(m_buffer.size() - m_stream->avail_out());
            clear();
            break;
         }

         // More data follows: try to process as a following stream
         // Remove stream1's unused output space so stream2's output
         // is placed immediately after stream1's data with no gap.
         m_buffer.resize(m_buffer.size() - m_stream->avail_out());
         const size_t read = (buf.size() - offset) - m_stream->avail_in();
         start();
         m_stream->next_in(buf.data() + offset + read, buf.size() - offset - read);
      }

      if(m_stream->avail_out() == 0) {
         const size_t added = add_or_throw<size_t>(m_buffer.size(), 8, "Compression output too large");
         const size_t new_size = add_or_throw(m_buffer.size(), added, "Compression output too large");
         m_buffer.resize(new_size);
         m_stream->next_out(m_buffer.data() + m_buffer.size() - added, added);
      } else if(m_stream->avail_in() == 0) {
         m_buffer.resize(m_buffer.size() - m_stream->avail_out());
         break;
      }
   }

   copy_mem(m_buffer.data(), buf.data(), offset);
   buf.swap(m_buffer);
}

void Stream_Decompression::update(secure_vector<uint8_t>& buf, size_t offset) {
   if(!m_stream) {
      if(buf.size() == offset) {
         return;
      }
      // Previous stream ended cleanly; re-initialize for a concatenated stream
      start();
   }
   process(buf, offset, m_stream->run_flag());
}

void Stream_Decompression::finish(secure_vector<uint8_t>& buf, size_t offset) {
   if(!m_stream) {
      if(buf.size() == offset) {
         return;
      }
      // Previous stream ended cleanly; re-initialize for a concatenated stream
      start();
   }

   process(buf, offset, m_stream->finish_flag());

   if(m_stream) {
      throw Invalid_State(fmt("{} finished but not at stream end", name()));
   }
}

}  // namespace Botan
