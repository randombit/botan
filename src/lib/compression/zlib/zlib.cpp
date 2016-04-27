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
#include <ctime>
#include <zlib.h>

namespace Botan {

BOTAN_REGISTER_COMPRESSION(Zlib_Compression, Zlib_Decompression);
BOTAN_REGISTER_COMPRESSION(Gzip_Compression, Gzip_Decompression);
BOTAN_REGISTER_COMPRESSION(Deflate_Compression, Deflate_Decompression);

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

      u32bit run_flag() const override { return Z_NO_FLUSH; }
      u32bit flush_flag() const override { return Z_SYNC_FLUSH; }
      u32bit finish_flag() const override { return Z_FINISH; }

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
            throw Exception("zlib deflate initialization failed");
         }

      ~Zlib_Compression_Stream()
         {
         ::deflateEnd(streamp());
         }

      bool run(u32bit flags) override
         {
         int rc = ::deflate(streamp(), flags);

         if(rc == Z_MEM_ERROR)
            throw Exception("zlib memory allocation failure");
         else if(rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR)
            throw Exception("zlib deflate error " + std::to_string(rc));

         return (rc == Z_STREAM_END);
         }
   };

class Zlib_Decompression_Stream : public Zlib_Stream
   {
   public:
      Zlib_Decompression_Stream(int wbits, int wbits_offset = 0)
         {
         int rc = ::inflateInit2(streamp(), compute_window_bits(wbits, wbits_offset));

         if(rc == Z_MEM_ERROR)
            throw Exception("zlib memory allocation failure");
         else if(rc != Z_OK)
            throw Exception("zlib inflate initialization failed");
         }

      ~Zlib_Decompression_Stream()
         {
         ::inflateEnd(streamp());
         }

      bool run(u32bit flags) override
         {
         int rc = ::inflate(streamp(), flags);

         if(rc == Z_MEM_ERROR)
            throw Exception("zlib memory allocation failure");
         else if(rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR)
            throw Exception("zlib inflate error " + std::to_string(rc));

         return (rc == Z_STREAM_END);
         }
   };

class Deflate_Compression_Stream : public Zlib_Compression_Stream
   {
   public:
      Deflate_Compression_Stream(size_t level, int wbits) :
         Zlib_Compression_Stream(level, wbits, -1) {}
   };

class Deflate_Decompression_Stream : public Zlib_Decompression_Stream
   {
   public:
      explicit Deflate_Decompression_Stream(int wbits) : Zlib_Decompression_Stream(wbits, -1) {}
   };

class Gzip_Compression_Stream : public Zlib_Compression_Stream
   {
   public:
      Gzip_Compression_Stream(size_t level, int wbits, byte os_code) :
         Zlib_Compression_Stream(level, wbits, 16)
         {
         clear_mem(&m_header, 1);
         m_header.os = os_code;
         m_header.time = std::time(nullptr);

         int rc = deflateSetHeader(streamp(), &m_header);
         if(rc != Z_OK)
            throw Exception("setting gzip header failed");
         }

   private:
      ::gz_header m_header;
   };

class Gzip_Decompression_Stream : public Zlib_Decompression_Stream
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
   return new Gzip_Compression_Stream(level, 15, m_os_code);
   }

Compression_Stream* Gzip_Decompression::make_stream() const
   {
   return new Gzip_Decompression_Stream(15);
   }

}
