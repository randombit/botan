/*
* Zlib Compressor
* (C) 2001 Peter J Jones
*     2001-2007,2014 Jack Lloyd
*     2006 Matt Johnston
*
* Distributed under the terms of the Botan license
*/

#include <botan/zlib.h>
#include <botan/internal/comp_util.h>
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

      u32bit run_flag() const override { return Z_NO_FLUSH; }
      u32bit flush_flag() const override { return Z_FULL_FLUSH; }
      u32bit finish_flag() const override { return Z_FINISH; }
   };

class Zlib_Compression_Stream : public Zlib_Stream
   {
   public:
      Zlib_Compression_Stream(size_t level, bool raw_deflate)
         {
         // FIXME: allow specifiying memLevel and strategy
         int rc = deflateInit2(streamp(), level, Z_DEFLATED,
                               (raw_deflate ? -15 : 15), 8, Z_DEFAULT_STRATEGY);
         if(rc != Z_OK)
            throw std::runtime_error("zlib deflate initialization failed");
         }

      ~Zlib_Compression_Stream()
         {
         deflateEnd(streamp());
         }

      bool run(u32bit flags) override
         {
         int rc = deflate(streamp(), flags);

         if(rc == Z_MEM_ERROR)
            throw std::bad_alloc();
         else if(rc != Z_OK && rc != Z_STREAM_END)
            throw std::runtime_error("zlib deflate error");

         return (rc == Z_STREAM_END);
         }
   };

class Zlib_Decompression_Stream : public Zlib_Stream
   {
   public:
      Zlib_Decompression_Stream(bool raw_deflate)
         {
         int rc = inflateInit2(streamp(), (raw_deflate ? -15 : 15));

         if(rc == Z_MEM_ERROR)
            throw std::bad_alloc();
         else if(rc != Z_OK)
            throw std::runtime_error("zlib inflate initialization failed");
         }

      ~Zlib_Decompression_Stream()
         {
         inflateEnd(streamp());
         }

      bool run(u32bit flags) override
         {
         int rc = inflate(streamp(), flags);

         if(rc == Z_MEM_ERROR)
            throw std::bad_alloc();
         else if(rc != Z_OK && rc != Z_STREAM_END)
            throw std::runtime_error("zlib deflate error");

         return (rc == Z_STREAM_END);
         }
   };

}

Compression_Stream* Zlib_Compression::make_stream() const
   {
   return new Zlib_Compression_Stream(m_level, m_raw_deflate);
   }

Compression_Stream* Zlib_Decompression::make_stream() const
   {
   return new Zlib_Decompression_Stream(m_raw_deflate);
   }

}
