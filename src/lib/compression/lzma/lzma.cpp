/*
* Lzma Compressor
* (C) 2001 Peter J Jones
*     2001-2007,2014 Jack Lloyd
*     2006 Matt Johnston
*     2012 Vojtech Kral
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/lzma.h>
#include <botan/internal/compress_utils.h>
#include <lzma.h>

namespace Botan {

BOTAN_REGISTER_COMPRESSION(LZMA_Compression, LZMA_Decompression);

namespace {

class LZMA_Stream : public Zlib_Style_Stream<lzma_stream, byte>
   {
   public:
      LZMA_Stream()
         {
         auto a = new ::lzma_allocator;
         a->opaque = alloc();
         a->alloc = Compression_Alloc_Info::malloc<size_t>;
         a->free = Compression_Alloc_Info::free;
         streamp()->allocator = a;
         }

      ~LZMA_Stream()
         {
         ::lzma_end(streamp());
         delete streamp()->allocator;
         }

      bool run(u32bit flags) override
         {
         lzma_ret rc = ::lzma_code(streamp(), static_cast<lzma_action>(flags));

         if(rc == LZMA_MEM_ERROR)
            throw Exception("lzma memory allocation failed");
         else if (rc != LZMA_OK && rc != LZMA_STREAM_END)
            throw Exception("Lzma error");

         return (rc == LZMA_STREAM_END);
         }

      u32bit run_flag() const override { return LZMA_RUN; }
      u32bit flush_flag() const override { return LZMA_FULL_FLUSH; }
      u32bit finish_flag() const override { return LZMA_FINISH; }
   };

class LZMA_Compression_Stream : public LZMA_Stream
   {
   public:
      explicit LZMA_Compression_Stream(size_t level)
         {
         lzma_ret rc = ::lzma_easy_encoder(streamp(), level, LZMA_CHECK_CRC64);

         if(rc == LZMA_MEM_ERROR)
            throw Exception("lzma memory allocation failed");
         else if(rc != LZMA_OK)
            throw Exception("lzma compress initialization failed");
         }
   };

class LZMA_Decompression_Stream : public LZMA_Stream
   {
   public:
      LZMA_Decompression_Stream()
         {
         lzma_ret rc = ::lzma_stream_decoder(streamp(), UINT64_MAX,
                                             LZMA_TELL_UNSUPPORTED_CHECK);

         if(rc == LZMA_MEM_ERROR)
            throw Exception("lzma memory allocation failed");
         else if(rc != LZMA_OK)
            throw Exception("Bad setting in lzma_stream_decoder");
         }
   };

}

Compression_Stream* LZMA_Compression::make_stream() const
   {
   return new LZMA_Compression_Stream(m_level);
   }

Compression_Stream* LZMA_Decompression::make_stream() const
   {
   return new LZMA_Decompression_Stream;
   }

}
