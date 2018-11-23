/*
* Bzip2 Compressor
* (C) 2001 Peter J Jones
*     2001-2007,2014 Jack Lloyd
*     2006 Matt Johnston
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bzip2.h>
#include <botan/exceptn.h>
#include <botan/internal/compress_utils.h>

#define BZ_NO_STDIO
#include <bzlib.h>

namespace Botan {

namespace {

class Bzip2_Stream : public Zlib_Style_Stream<bz_stream, char>
   {
   public:
      Bzip2_Stream()
         {
         streamp()->opaque = alloc();
         streamp()->bzalloc = Compression_Alloc_Info::malloc<int>;
         streamp()->bzfree = Compression_Alloc_Info::free;
         }

      uint32_t run_flag() const override { return BZ_RUN; }
      uint32_t flush_flag() const override { return BZ_FLUSH; }
      uint32_t finish_flag() const override { return BZ_FINISH; }
   };

class Bzip2_Compression_Stream final : public Bzip2_Stream
   {
   public:
      explicit Bzip2_Compression_Stream(size_t block_size)
         {
         /*
         * Defaults to 900k blocks as the computation cost of
         * compression is not overly affected by the size, though
         * more memory is required.
         */
         if(block_size == 0 || block_size >= 9)
            block_size = 9;

         int rc = BZ2_bzCompressInit(streamp(), block_size, 0, 0);

         if(rc != BZ_OK)
            throw Compression_Error("BZ2_bzCompressInit", ErrorType::Bzip2Error, rc);
         }

      ~Bzip2_Compression_Stream()
         {
         BZ2_bzCompressEnd(streamp());
         }

      bool run(uint32_t flags) override
         {
         int rc = BZ2_bzCompress(streamp(), flags);

         if(rc < 0)
            throw Compression_Error("BZ2_bzCompress", ErrorType::Bzip2Error, rc);

         return (rc == BZ_STREAM_END);
         }
   };

class Bzip2_Decompression_Stream final : public Bzip2_Stream
   {
   public:
      Bzip2_Decompression_Stream()
         {
         int rc = BZ2_bzDecompressInit(streamp(), 0, 0);

         if(rc != BZ_OK)
            throw Compression_Error("BZ2_bzDecompressInit", ErrorType::Bzip2Error, rc);
         }

      ~Bzip2_Decompression_Stream()
         {
         BZ2_bzDecompressEnd(streamp());
         }

      bool run(uint32_t) override
         {
         int rc = BZ2_bzDecompress(streamp());

         if(rc != BZ_OK && rc != BZ_STREAM_END)
            throw Compression_Error("BZ2_bzDecompress", ErrorType::Bzip2Error, rc);

         return (rc == BZ_STREAM_END);
         }
   };

}

Compression_Stream* Bzip2_Compression::make_stream(size_t comp_level) const
   {
   return new Bzip2_Compression_Stream(comp_level);
   }

Compression_Stream* Bzip2_Decompression::make_stream() const
   {
   return new Bzip2_Decompression_Stream;
   }

}
