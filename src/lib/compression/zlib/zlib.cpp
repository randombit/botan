/*
* Zlib Compressor
* (C) 2001 Peter J Jones
*     2001-2007,2014 Jack Lloyd
*     2006 Matt Johnston
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/zlib.h>
#include <botan/internal/compress_utils.h>
#include <botan/exceptn.h>
#include <zlib.h>

namespace Botan {

namespace {

class Zlib_Stream : public Zlib_Style_Stream<z_stream, Bytef>
   {
   public:
      Zlib_Stream()
         {
         streamp()->opaque = alloc();
         streamp()->zalloc = Compression_Alloc_Info::malloc<unsigned int>;
         streamp()->zfree = Compression_Alloc_Info::free;
         }

      uint32_t run_flag() const override { return Z_NO_FLUSH; }
      uint32_t flush_flag() const override { return Z_SYNC_FLUSH; }
      uint32_t finish_flag() const override { return Z_FINISH; }

      int compute_window_bits(int wbits, int wbits_offset) const
         {
         if(wbits_offset == -1)
            return -wbits;
         else
            return wbits + wbits_offset;
         }
   };

class Zlib_Compression_Stream : public Zlib_Stream
   {
   public:
      Zlib_Compression_Stream(size_t level, int wbits, int wbits_offset = 0)
         {
         wbits = compute_window_bits(wbits, wbits_offset);

         if(level >= 9)
            level = 9;
         else if(level == 0)
            level = 6;

         int rc = ::deflateInit2(streamp(), level, Z_DEFLATED, wbits, 8, Z_DEFAULT_STRATEGY);

         if(rc != Z_OK)
            throw Compression_Error("deflateInit2", ErrorType::ZlibError, rc);
         }

      ~Zlib_Compression_Stream()
         {
         ::deflateEnd(streamp());
         }

      bool run(uint32_t flags) override
         {
         int rc = ::deflate(streamp(), flags);

         if(rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR)
            throw Compression_Error("zlib deflate", ErrorType::ZlibError, rc);

         return (rc == Z_STREAM_END);
         }
   };

class Zlib_Decompression_Stream : public Zlib_Stream
   {
   public:
      Zlib_Decompression_Stream(int wbits, int wbits_offset = 0)
         {
         int rc = ::inflateInit2(streamp(), compute_window_bits(wbits, wbits_offset));

         if(rc != Z_OK)
            throw Compression_Error("inflateInit2", ErrorType::ZlibError, rc);
         }

      ~Zlib_Decompression_Stream()
         {
         ::inflateEnd(streamp());
         }

      bool run(uint32_t flags) override
         {
         int rc = ::inflate(streamp(), flags);

         if(rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR)
            throw Compression_Error("zlib inflate", ErrorType::ZlibError, rc);

         return (rc == Z_STREAM_END);
         }
   };

class Deflate_Compression_Stream final : public Zlib_Compression_Stream
   {
   public:
      Deflate_Compression_Stream(size_t level, int wbits) :
         Zlib_Compression_Stream(level, wbits, -1) {}
   };

class Deflate_Decompression_Stream final : public Zlib_Decompression_Stream
   {
   public:
      explicit Deflate_Decompression_Stream(int wbits) : Zlib_Decompression_Stream(wbits, -1) {}
   };

class Gzip_Compression_Stream final : public Zlib_Compression_Stream
   {
   public:
      Gzip_Compression_Stream(size_t level, int wbits, uint8_t os_code, uint64_t hdr_time) :
         Zlib_Compression_Stream(level, wbits, 16)
         {
         clear_mem(&m_header, 1);
         m_header.os = os_code;
         m_header.time = static_cast<uLong>(hdr_time);

         int rc = deflateSetHeader(streamp(), &m_header);
         if(rc != Z_OK)
            throw Compression_Error("deflateSetHeader", ErrorType::ZlibError, rc);
         }

   private:
      ::gz_header m_header;
   };

class Gzip_Decompression_Stream final : public Zlib_Decompression_Stream
   {
   public:
      explicit Gzip_Decompression_Stream(int wbits) : Zlib_Decompression_Stream(wbits, 16) {}
   };

}

Compression_Stream* Zlib_Compression::make_stream(size_t level) const
   {
   return new Zlib_Compression_Stream(level, 15);
   }

Compression_Stream* Zlib_Decompression::make_stream() const
   {
   return new Zlib_Decompression_Stream(15);
   }

Compression_Stream* Deflate_Compression::make_stream(size_t level) const
   {
   return new Deflate_Compression_Stream(level, 15);
   }

Compression_Stream* Deflate_Decompression::make_stream() const
   {
   return new Deflate_Decompression_Stream(15);
   }

Compression_Stream* Gzip_Compression::make_stream(size_t level) const
   {
   return new Gzip_Compression_Stream(level, 15, m_os_code, m_hdr_time);
   }

Compression_Stream* Gzip_Decompression::make_stream() const
   {
   return new Gzip_Decompression_Stream(15);
   }

}
