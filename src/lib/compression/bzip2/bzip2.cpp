/*
* Bzip Compressor
* (C) 2001 Peter J Jones
*     2001-2007,2014 Jack Lloyd
*     2006 Matt Johnston
*
* Distributed under the terms of the Botan license
*/

#include <botan/bzip2.h>
#include <botan/internal/comp_util.h>

#define BZ_NO_STDIO
#include <bzlib.h>

namespace Botan {

namespace {

class Bzip_Stream : public Zlib_Style_Stream<bz_stream, char>
   {
   public:
      Bzip_Stream()
         {
         streamp()->opaque = alloc();
         streamp()->bzalloc = Compression_Alloc_Info::malloc<int>;
         streamp()->bzfree = Compression_Alloc_Info::free;
         }

      u32bit run_flag() const override { return BZ_RUN; }
      u32bit flush_flag() const override { return BZ_FLUSH; }
      u32bit finish_flag() const override { return BZ_FINISH; }
   };

class Bzip_Compression_Stream : public Bzip_Stream
   {
   public:
      Bzip_Compression_Stream(size_t level)
         {
         int rc = BZ2_bzCompressInit(streamp(), level, 0, 0);

         if(rc == BZ_MEM_ERROR)
            throw std::bad_alloc();
         else if(rc != BZ_OK)
            throw std::runtime_error("bzip compress initialization failed");
         }

      ~Bzip_Compression_Stream()
         {
         BZ2_bzCompressEnd(streamp());
         }

      bool run(u32bit flags) override
         {
         int rc = BZ2_bzCompress(streamp(), flags);

         if(rc == BZ_MEM_ERROR)
            throw std::bad_alloc();
         else if(rc < 0)
            throw std::runtime_error("bzip compress error");

         return (rc == BZ_STREAM_END);
         }

   private:
      size_t m_level;
   };

class Bzip_Decompression_Stream : public Bzip_Stream
   {
   public:
      Bzip_Decompression_Stream()
         {
         int rc = BZ2_bzDecompressInit(streamp(), 0, 0);

         if(rc == BZ_MEM_ERROR)
            throw std::bad_alloc();
         else if(rc != BZ_OK)
            throw std::runtime_error("bzip decompress initialization failed");
         }

      ~Bzip_Decompression_Stream()
         {
         BZ2_bzDecompressEnd(streamp());
         }

      bool run(u32bit) override
         {
         int rc = BZ2_bzDecompress(streamp());

         if(rc == BZ_MEM_ERROR)
            throw std::bad_alloc();
         else if(rc != BZ_OK && rc != BZ_STREAM_END)
            throw std::runtime_error("bzip decompress error");

         return (rc == BZ_STREAM_END);
         }
   };

}

Compression_Stream* Bzip_Compression::make_stream() const
   {
   return new Bzip_Compression_Stream(m_level);
   }

Compression_Stream* Bzip_Decompression::make_stream() const
   {
   return new Bzip_Decompression_Stream;
   }

}
