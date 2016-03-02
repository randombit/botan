/*
* Compression Transform
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/compression.h>
#include <botan/internal/compress_utils.h>
#include <botan/mem_ops.h>
#include <cstdlib>

namespace Botan {

void* Compression_Alloc_Info::do_malloc(size_t n, size_t size)
   {
   const size_t total_size = n * size;

   BOTAN_ASSERT_EQUAL(total_size / size, n, "Overflow check");

   // TODO maximum length check here?

   void* ptr = std::malloc(total_size);

   /*
   * Return null rather than throwing here as we are being called by a
   * C library and it may not be possible for an exception to unwind
   * the call stack from here. The compression library is expecting a
   * function written in C and a null return on error, which it will
   * send upwards to the compression wrappers.
   */

   if(ptr)
      {
      std::memset(ptr, 0, total_size);
      m_current_allocs[ptr] = total_size;
      }

   return ptr;
   }

void Compression_Alloc_Info::do_free(void* ptr)
   {
   if(ptr)
      {
      auto i = m_current_allocs.find(ptr);

      if(i == m_current_allocs.end())
         throw Exception("Compression_Alloc_Info::free got pointer not allocated by us");

      zero_mem(ptr, i->second);
      std::free(ptr);
      m_current_allocs.erase(i);
      }
   }

namespace {

Compressor_Transform* do_make_compressor(const std::string& type, const std::string& suffix)
   {
   const std::map<std::string, std::string> trans{
      {"zlib", "Zlib"},
      {"deflate", "Deflate"},
      {"gzip", "Gzip"},
      {"gz", "Gzip"},
      {"bzip2", "Bzip2"},
      {"bz2", "Bzip2"},
      {"lzma", "LZMA"},
      {"xz", "LZMA"}};

   auto i = trans.find(type);

   if(i == trans.end())
      return nullptr;

   const std::string t_name = i->second + suffix;

   std::unique_ptr<Transform> t(get_transform(t_name));

   if(!t)
      return nullptr;

   Compressor_Transform* r = dynamic_cast<Compressor_Transform*>(t.get());
   if(!r)
      throw Exception("Bad cast of compression object " + t_name);

   t.release();
   return r;
   }

}

Compressor_Transform* make_compressor(const std::string& type, size_t level)
   {
   return do_make_compressor(type, "_Compression(" + std::to_string(level) + ")");
   }

Compressor_Transform* make_decompressor(const std::string& type)
   {
   return do_make_compressor(type, "_Decompression");
   }

void Stream_Compression::clear()
   {
   m_stream.reset();
   }

secure_vector<byte> Stream_Compression::start_raw(const byte[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   m_stream.reset(make_stream());
   return secure_vector<byte>();
   }

void Stream_Compression::process(secure_vector<byte>& buf, size_t offset, u32bit flags)
   {
   BOTAN_ASSERT(m_stream, "Initialized");
   BOTAN_ASSERT(buf.size() >= offset, "Offset is sane");

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
      m_stream->run(flags);

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

void Stream_Compression::update(secure_vector<byte>& buf, size_t offset)
   {
   BOTAN_ASSERT(m_stream, "Initialized");
   process(buf, offset, m_stream->run_flag());
   }

void Stream_Compression::flush(secure_vector<byte>& buf, size_t offset)
   {
   BOTAN_ASSERT(m_stream, "Initialized");
   process(buf, offset, m_stream->flush_flag());
   }

void Stream_Compression::finish(secure_vector<byte>& buf, size_t offset)
   {
   BOTAN_ASSERT(m_stream, "Initialized");
   process(buf, offset, m_stream->finish_flag());
   clear();
   }

void Stream_Decompression::clear()
   {
   m_stream.reset();
   }

secure_vector<byte> Stream_Decompression::start_raw(const byte[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   m_stream.reset(make_stream());

   return secure_vector<byte>();
   }

void Stream_Decompression::process(secure_vector<byte>& buf, size_t offset, u32bit flags)
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

void Stream_Decompression::update(secure_vector<byte>& buf, size_t offset)
   {
   process(buf, offset, m_stream->run_flag());
   }

void Stream_Decompression::finish(secure_vector<byte>& buf, size_t offset)
   {
   if(buf.size() != offset || m_stream.get())
      process(buf, offset, m_stream->finish_flag());

   if(m_stream.get())
      throw Exception(name() + " finished but not at stream end");
   }

}
