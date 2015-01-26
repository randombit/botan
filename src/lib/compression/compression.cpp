/*
* Compression Transform
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/compression.h>

#if defined(BOTAN_HAS_ZLIB_TRANSFORM)
  #include <botan/zlib.h>
#endif

#if defined(BOTAN_HAS_BZIP2_TRANSFORM)
  #include <botan/bzip2.h>
#endif

#if defined(BOTAN_HAS_LZMA_TRANSFORM)
  #include <botan/lzma.h>
#endif

namespace Botan {

Compressor_Transformation* make_compressor(const std::string& type, size_t level)
   {
#if defined(BOTAN_HAS_ZLIB_TRANSFORM)
   if(type == "zlib")
      return new Zlib_Compression(level);
   if(type == "deflate")
      return new Deflate_Compression(level);
   if(type == "gzip" || type == "gz")
      return new Gzip_Compression(level);
#endif

#if defined(BOTAN_HAS_BZIP2_TRANSFORM)
   if(type == "bzip2" || type == "bz2")
      return new Bzip2_Compression(level);
#endif

#if defined(BOTAN_HAS_LZMA_TRANSFORM)
   if(type == "lzma" || type == "xz")
      return new LZMA_Compression(level);
#endif

   throw std::runtime_error("Unknown compression type " + type);
   }

Compressor_Transformation* make_decompressor(const std::string& type)
   {
#if defined(BOTAN_HAS_ZLIB_TRANSFORM)
   if(type == "zlib")
      return new Zlib_Decompression;
   if(type == "deflate")
      return new Deflate_Decompression;
   if(type == "gzip" || type == "gz")
      return new Gzip_Decompression;
#endif

#if defined(BOTAN_HAS_BZIP2_TRANSFORM)
   if(type == "bzip2" || type == "bz2")
      return new Bzip2_Decompression;
#endif

#if defined(BOTAN_HAS_LZMA_TRANSFORM)
   if(type == "lzma" || type == "xz")
      return new LZMA_Decompression;
#endif

   throw std::runtime_error("Unknown compression type " + type);
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

   m_stream->next_in(&buf[offset], buf.size() - offset);
   m_stream->next_out(&m_buffer[offset], m_buffer.size() - offset);

   while(true)
      {
      m_stream->run(flags);

      if(m_stream->avail_out() == 0)
         {
         const size_t added = 8 + m_buffer.size();
         m_buffer.resize(m_buffer.size() + added);
         m_stream->next_out(&m_buffer[m_buffer.size() - added], added);
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
   process(buf, offset, m_stream->run_flag());
   }

void Stream_Compression::flush(secure_vector<byte>& buf, size_t offset)
   {
   process(buf, offset, m_stream->flush_flag());
   }

void Stream_Compression::finish(secure_vector<byte>& buf, size_t offset)
   {
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

   m_stream->next_in(&buf[offset], buf.size() - offset);
   m_stream->next_out(&m_buffer[offset], m_buffer.size() - offset);

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
         m_stream->next_in(&buf[offset + read], buf.size() - offset - read);
         }

      if(m_stream->avail_out() == 0)
         {
         const size_t added = 8 + m_buffer.size();
         m_buffer.resize(m_buffer.size() + added);
         m_stream->next_out(&m_buffer[m_buffer.size() - added], added);
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
      throw std::runtime_error(name() + " finished but not at stream end");
   }

}
