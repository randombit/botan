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
#include <botan/exceptn.h>
#include <lzma.h>

namespace Botan {

namespace {

class LZMA_Stream : public Zlib_Style_Stream<lzma_stream, uint8_t>
   {
   public:
      LZMA_Stream()
         {
         m_allocator.opaque = alloc();
         m_allocator.alloc = Compression_Alloc_Info::malloc<size_t>;
         m_allocator.free = Compression_Alloc_Info::free;
         streamp()->allocator = &m_allocator;
         }

      ~LZMA_Stream()
         {
         ::lzma_end(streamp());
         }

      bool run(uint32_t flags) override
         {
         lzma_ret rc = ::lzma_code(streamp(), static_cast<lzma_action>(flags));

         if(rc != LZMA_OK && rc != LZMA_STREAM_END)
            throw Compression_Error("lzma_code", ErrorType::LzmaError, rc);

         return (rc == LZMA_STREAM_END);
         }

      uint32_t run_flag() const override { return LZMA_RUN; }
      uint32_t flush_flag() const override { return LZMA_FULL_FLUSH; }
      uint32_t finish_flag() const override { return LZMA_FINISH; }
   private:
      ::lzma_allocator m_allocator;
   };

class LZMA_Compression_Stream final : public LZMA_Stream
   {
   public:
      explicit LZMA_Compression_Stream(size_t level)
         {
         if(level == 0)
            level = 6; // default
         else if(level > 9)
            level = 9; // clamp to maximum allowed value

         lzma_ret rc = ::lzma_easy_encoder(streamp(), level, LZMA_CHECK_CRC64);

         if(rc != LZMA_OK)
            throw Compression_Error("lzam_easy_encoder", ErrorType::LzmaError, rc);
         }
   };

class LZMA_Decompression_Stream final : public LZMA_Stream
   {
   public:
      LZMA_Decompression_Stream()
         {
         lzma_ret rc = ::lzma_stream_decoder(streamp(), UINT64_MAX,
                                             LZMA_TELL_UNSUPPORTED_CHECK);

         if(rc != LZMA_OK)
            throw Compression_Error("lzma_stream_decoder", ErrorType::LzmaError, rc);
         }
   };

}

Compression_Stream* LZMA_Compression::make_stream(size_t level) const
   {
   return new LZMA_Compression_Stream(level);
   }

Compression_Stream* LZMA_Decompression::make_stream() const
   {
   return new LZMA_Decompression_Stream;
   }

}
