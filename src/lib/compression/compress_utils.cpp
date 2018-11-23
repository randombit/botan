/*
* Compression Utils
* (C) 2014,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/compress_utils.h>
#include <botan/exceptn.h>
#include <cstdlib>

namespace Botan {

void* Compression_Alloc_Info::do_malloc(size_t n, size_t size)
   {
   // TODO maximum length check here?
   void* ptr = std::calloc(n, size);

   /*
   * Return null rather than throwing here as we are being called by a
   * C library and it may not be possible for an exception to unwind
   * the call stack from here. The compression library is expecting a
   * function written in C and a null return on error, which it will
   * send upwards to the compression wrappers.
   */

   if(ptr)
      {
      m_current_allocs[ptr] = n * size;
      }

   return ptr;
   }

void Compression_Alloc_Info::do_free(void* ptr)
   {
   if(ptr)
      {
      auto i = m_current_allocs.find(ptr);

      if(i == m_current_allocs.end())
         throw Internal_Error("Compression_Alloc_Info::free got pointer not allocated by us");

      secure_scrub_memory(ptr, i->second);
      std::free(ptr);
      m_current_allocs.erase(i);
      }
   }

void Stream_Compression::clear()
   {
   m_stream.reset();
   }

void Stream_Compression::start(size_t level)
   {
   m_stream.reset(make_stream(level));
   }

void Stream_Compression::process(secure_vector<uint8_t>& buf, size_t offset, uint32_t flags)
   {
   BOTAN_ASSERT(m_stream, "Initialized");
   BOTAN_ASSERT(buf.size() >= offset, "Offset is sane");

   // bzip doesn't like being called with no input and BZ_RUN
   if(buf.size() == offset && flags == m_stream->run_flag())
      {
      return;
      }

   if(m_buffer.size() < buf.size() + offset)
      m_buffer.resize(buf.size() + offset);

   // If the output buffer has zero length, .data() might return nullptr. This would
   // make some compression algorithms (notably those provided by zlib) fail.
   // Any small positive value works fine, but we choose 32 as it is the smallest power
   // of two that is large enough to hold all the headers and trailers of the common
   // formats, preventing further resizings to make room for output data.
   if(m_buffer.size() == 0)
      m_buffer.resize(32);

   m_stream->next_in(buf.data() + offset, buf.size() - offset);
   m_stream->next_out(m_buffer.data() + offset, m_buffer.size() - offset);

   while(true)
      {
      const bool stream_end = m_stream->run(flags);

      if(stream_end)
         {
         BOTAN_ASSERT(m_stream->avail_in() == 0, "After stream is done, no input remains to be processed");
         m_buffer.resize(m_buffer.size() - m_stream->avail_out());
         break;
         }
      else if(m_stream->avail_out() == 0)
         {
         const size_t added = 8 + m_buffer.size();
         m_buffer.resize(m_buffer.size() + added);
         m_stream->next_out(m_buffer.data() + m_buffer.size() - added, added);
         }
      else if(m_stream->avail_in() == 0)
         {
         m_buffer.resize(m_buffer.size() - m_stream->avail_out());
         break;
         }
      }

   copy_mem(m_buffer.data(), buf.data(), offset);
   buf.swap(m_buffer);
   }

void Stream_Compression::update(secure_vector<uint8_t>& buf, size_t offset, bool flush)
   {
   BOTAN_ASSERT(m_stream, "Initialized");
   process(buf, offset, flush ? m_stream->flush_flag() : m_stream->run_flag());
   }

void Stream_Compression::finish(secure_vector<uint8_t>& buf, size_t offset)
   {
   BOTAN_ASSERT(m_stream, "Initialized");
   process(buf, offset, m_stream->finish_flag());
   clear();
   }

void Stream_Decompression::clear()
   {
   m_stream.reset();
   }

void Stream_Decompression::start()
   {
   m_stream.reset(make_stream());
   }

void Stream_Decompression::process(secure_vector<uint8_t>& buf, size_t offset, uint32_t flags)
   {
   BOTAN_ASSERT(m_stream, "Initialized");
   BOTAN_ASSERT(buf.size() >= offset, "Offset is sane");

   if(m_buffer.size() < buf.size() + offset)
      m_buffer.resize(buf.size() + offset);

   m_stream->next_in(buf.data() + offset, buf.size() - offset);
   m_stream->next_out(m_buffer.data() + offset, m_buffer.size() - offset);

   while(true)
      {
      const bool stream_end = m_stream->run(flags);

      if(stream_end)
         {
         if(m_stream->avail_in() == 0) // all data consumed?
            {
            m_buffer.resize(m_buffer.size() - m_stream->avail_out());
            clear();
            break;
            }

         // More data follows: try to process as a following stream
         const size_t read = (buf.size() - offset) - m_stream->avail_in();
         start();
         m_stream->next_in(buf.data() + offset + read, buf.size() - offset - read);
         }

      if(m_stream->avail_out() == 0)
         {
         const size_t added = 8 + m_buffer.size();
         m_buffer.resize(m_buffer.size() + added);
         m_stream->next_out(m_buffer.data() + m_buffer.size() - added, added);
         }
      else if(m_stream->avail_in() == 0)
         {
         m_buffer.resize(m_buffer.size() - m_stream->avail_out());
         break;
         }
      }

   copy_mem(m_buffer.data(), buf.data(), offset);
   buf.swap(m_buffer);
   }

void Stream_Decompression::update(secure_vector<uint8_t>& buf, size_t offset)
   {
   process(buf, offset, m_stream->run_flag());
   }

void Stream_Decompression::finish(secure_vector<uint8_t>& buf, size_t offset)
   {
   if(buf.size() != offset || m_stream.get())
      process(buf, offset, m_stream->finish_flag());

   if(m_stream.get())
      throw Invalid_State(name() + " finished but not at stream end");
   }

}
