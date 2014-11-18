/*
* Filter interface for compression
* (C) 2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/comp_filter.h>

#if defined(BOTAN_HAS_ZLIB_TRANSFORM)
  #include <botan/zlib.h>
#endif

#if defined(BOTAN_HAS_BZIP_TRANSFORM)
  #include <botan/bzip.h>
#endif

#if defined(BOTAN_HAS_LZMA_TRANSFORM)
  #include <botan/lzma.h>
#endif

namespace Botan {

namespace {

Compressor_Transformation* make_compressor(const std::string& type, size_t level)
   {
#if defined(BOTAN_HAS_ZLIB_TRANSFORM)
   if(type == "zlib")
      return new Zlib_Compression(level, false);
   if(type == "deflate")
      return new Zlib_Compression(level, true);
#endif

#if defined(BOTAN_HAS_BZIP_TRANSFORM)
   if(type == "bzip2")
      return new Bzip_Compression(level);
#endif

#if defined(BOTAN_HAS_LZMA_TRANSFORM)
   if(type == "lzma")
      return new LZMA_Compression(level);
#endif

   throw std::runtime_error("Unknown compression type " + type);
   }

Compressor_Transformation* make_decompressor(const std::string& type)
   {
#if defined(BOTAN_HAS_ZLIB_TRANSFORM)
   if(type == "zlib")
      return new Zlib_Decompression(false);
   if(type == "deflate")
      return new Zlib_Decompression(true);
#endif

#if defined(BOTAN_HAS_BZIP_TRANSFORM)
   if(type == "bzip2")
      return new Bzip_Decompression;
#endif

#if defined(BOTAN_HAS_LZMA_TRANSFORM)
   if(type == "lzma")
      return new LZMA_Decompression;
#endif

   throw std::runtime_error("Unknown compression type " + type);
   }

}

Compression_Filter::Compression_Filter(const std::string& type, size_t level) :
   Compression_Decompression_Filter(make_compressor(type, level))
   {
   }

Decompression_Filter::Decompression_Filter(const std::string& type) :
   Compression_Decompression_Filter(make_decompressor(type))
   {
   }

Compression_Decompression_Filter::Compression_Decompression_Filter(Compressor_Transformation* transform) :
   m_transform(transform)
   {
   }

std::string Compression_Decompression_Filter::name() const
   {
   return m_transform->name();
   }

void Compression_Decompression_Filter::start_msg()
   {
   send(m_transform->start());
   }

void Compression_Decompression_Filter::write(const byte input[], size_t input_length)
   {
   while(input_length)
      {
      const size_t take = std::min<size_t>({4096, m_buffer.capacity(), input_length});

      m_buffer.assign(input, input + take);
      m_transform->update(m_buffer);

      send(m_buffer);

      input += take;
      input_length -= take;
      }
   }

void Compression_Decompression_Filter::flush()
   {
   m_buffer.clear();
   m_transform->flush(m_buffer);
   send(m_buffer);
   }

void Compression_Decompression_Filter::end_msg()
   {
   m_buffer.clear();
   m_transform->finish(m_buffer);
   send(m_buffer);
   }

}
