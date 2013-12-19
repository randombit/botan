/*
* Lzma Compressor
* (C) 2001 Peter J Jones
*     2001-2007 Jack Lloyd
*     2006 Matt Johnston
*     2012 Vojtech Kral
*
* Distributed under the terms of the Botan license
*/

#include <botan/lzma.h>
#include <botan/exceptn.h>

#include <cstring>
#include <cstdlib>
#include <map>
#include <lzma.h>

namespace Botan {

namespace {

/*
* Allocation Information for Lzma
*/
class Lzma_Alloc_Info
   {
   public:
      std::map<void*, size_t> current_allocs;
   };

/*
* Allocation Function for Lzma
*/
void* lzma_malloc(void *opaque, size_t /*nmemb*/, size_t size)
   {
   Lzma_Alloc_Info* info = static_cast<Lzma_Alloc_Info*>(opaque);
   void* ptr = std::malloc(size);      // It is guaranteed by liblzma doc that nmemb is always set to 1
   info->current_allocs[ptr] = size;
   return ptr;
   }

/*
* Allocation Function for Lzma
*/
void lzma_free(void *opaque, void *ptr)
   {
   if(!ptr) return;       // liblzma sometimes does pass zero ptr

   Lzma_Alloc_Info* info = static_cast<Lzma_Alloc_Info*>(opaque);
   auto i = info->current_allocs.find(ptr);
   if(i == info->current_allocs.end())
      throw Invalid_Argument("lzma_free: Got pointer not allocated by us");

   std::memset(ptr, 0, i->second);
   std::free(ptr);
   }

}

/**
* Wrapper Type for lzma_stream
*/
class Lzma_Stream
   {
   public:
      /**
      * Underlying stream
      */
      lzma_stream stream;

      /**
      * Constructor
      */
      Lzma_Stream() :
         stream(LZMA_STREAM_INIT)
         {
         stream.allocator = new lzma_allocator;
         stream.allocator->alloc = lzma_malloc;
         stream.allocator->free = lzma_free;
         stream.allocator->opaque = new Lzma_Alloc_Info;
         }

      /**
      * Destructor
      */
      ~Lzma_Stream()
         {
         Lzma_Alloc_Info* info = static_cast<Lzma_Alloc_Info*>(stream.allocator->opaque);
         delete info;
         delete stream.allocator;
         std::memset(&stream, 0, sizeof(lzma_stream));
         }
   };

/*
* Lzma_Compression Constructor
*/
Lzma_Compression::Lzma_Compression(size_t l) :
   level((l >= 9) ? 9 : l),
   buffer(DEFAULT_BUFFERSIZE),
   lzma(0)
   {
   }

/*
* Start Compressing with Lzma
*/
void Lzma_Compression::start_msg()
   {
   clear();
   lzma = new Lzma_Stream;

   lzma_ret ret = lzma_easy_encoder(&(lzma->stream), level, LZMA_CHECK_CRC64);

   if(ret == LZMA_MEM_ERROR)
      throw Memory_Exhaustion();
   else if(ret != LZMA_OK)
      throw Invalid_Argument("Bad setting in lzma_easy_encoder");
   }

/*
* Compress Input with Lzma
*/
void Lzma_Compression::write(const byte input[], size_t length)
   {
   lzma->stream.next_in = static_cast<const uint8_t*>(input);
   lzma->stream.avail_in = length;

   while(lzma->stream.avail_in != 0)
      {
      lzma->stream.next_out = static_cast<uint8_t*>(&buffer[0]);
      lzma->stream.avail_out = buffer.size();

      lzma_ret ret = lzma_code(&(lzma->stream), LZMA_RUN);

      if(ret == LZMA_MEM_ERROR)
         throw Memory_Exhaustion();
      else if (ret != LZMA_OK)
         throw std::runtime_error("Lzma compression: Error writing");

      send(&buffer[0], buffer.size() - lzma->stream.avail_out);
      }
   }

/*
* Finish Compressing with Lzma
*/
void Lzma_Compression::end_msg()
   {
   lzma->stream.next_in = 0;
   lzma->stream.avail_in = 0;

   int ret = LZMA_OK;
   while(ret != LZMA_STREAM_END)
      {
      lzma->stream.next_out = reinterpret_cast<uint8_t*>(&buffer[0]);
      lzma->stream.avail_out = buffer.size();

      ret = lzma_code(&(lzma->stream), LZMA_FINISH);
      send(&buffer[0], buffer.size() - lzma->stream.avail_out);
      }

   clear();
   }

/*
* Flush the Lzma Compressor
*/
void Lzma_Compression::flush()
   {
   lzma->stream.next_in = 0;
   lzma->stream.avail_in = 0;

   while(true)
      {
      lzma->stream.next_out = reinterpret_cast<uint8_t*>(&buffer[0]);
      lzma->stream.avail_out = buffer.size();

      lzma_ret ret = lzma_code(&(lzma->stream), LZMA_FULL_FLUSH);

      if(ret == LZMA_MEM_ERROR)
         throw Memory_Exhaustion();
      else if (ret != LZMA_OK && ret != LZMA_STREAM_END)
         throw std::runtime_error("Lzma compression: Error flushing");

      send(&buffer[0], buffer.size() - lzma->stream.avail_out);

      if(lzma->stream.avail_out == buffer.size())
         break;
      }
   }

/*
* Clean up Compression Context
*/
void Lzma_Compression::clear()
   {
   zeroise(buffer);

   if(lzma)
      {
      lzma_end(&(lzma->stream));
      delete lzma;
      lzma = 0;
      }
   }

/*
* Lzma_Decompression Constructor
*/
Lzma_Decompression::Lzma_Decompression() :
   buffer(DEFAULT_BUFFERSIZE),
   lzma(0),
   no_writes(true)
   {
   }

/*
* Start Decompressing with Lzma
*/
void Lzma_Decompression::start_msg()
   {
   clear();
   lzma = new Lzma_Stream;

   lzma_ret ret = lzma_stream_decoder(&(lzma->stream), UINT64_MAX, LZMA_TELL_UNSUPPORTED_CHECK | LZMA_CONCATENATED);

   if(ret == LZMA_MEM_ERROR)
      throw Memory_Exhaustion();
   else if(ret != LZMA_OK)
      throw Invalid_Argument("Bad setting in lzma_stream_decoder");
   }

/*
* Decompress Input with Lzma
*/
void Lzma_Decompression::write(const byte input_arr[], size_t length)
   {
   if(length) no_writes = false;

   const uint8_t* input = reinterpret_cast<const uint8_t*>(input_arr);

   lzma->stream.next_in = input;
   lzma->stream.avail_in = length;

   while(lzma->stream.avail_in != 0)
      {
      lzma->stream.next_out = reinterpret_cast<uint8_t*>(&buffer[0]);
      lzma->stream.avail_out = buffer.size();

      lzma_ret ret = lzma_code(&(lzma->stream), LZMA_RUN);

      if(ret != LZMA_OK && ret != LZMA_STREAM_END)
         {
         clear();
         if(ret == LZMA_DATA_ERROR)
            throw Decoding_Error("Lzma_Decompression: Data integrity error");
         else if(ret == LZMA_MEM_ERROR)
            throw Memory_Exhaustion();
         else
            throw std::runtime_error("Lzma decompression: Unknown error");
         }

      send(&buffer[0], buffer.size() - lzma->stream.avail_out);

      if(ret == LZMA_STREAM_END)
         {
         size_t read_from_block = length - lzma->stream.avail_in;
         start_msg();

         lzma->stream.next_in = input + read_from_block;
         lzma->stream.avail_in = length - read_from_block;

         input += read_from_block;
         length -= read_from_block;
         }
      }
   }

/*
* Finish Decompressing with Lzma
*/
void Lzma_Decompression::end_msg()
   {
   if(no_writes) return;
   lzma->stream.next_in = 0;
   lzma->stream.avail_in = 0;

   int ret = LZMA_OK;

   while(ret != LZMA_STREAM_END)
      {
      lzma->stream.next_out = reinterpret_cast<uint8_t*>(&buffer[0]);
      lzma->stream.avail_out = buffer.size();
      ret = lzma_code(&(lzma->stream), LZMA_FINISH);

      if(ret != LZMA_OK && ret != LZMA_STREAM_END)
         {
         clear();
         throw Decoding_Error("Lzma_Decompression: Error finalizing");
         }

      send(&buffer[0], buffer.size() - lzma->stream.avail_out);
      }

   clear();
   }

/*
* Clean up Decompression Context
*/
void Lzma_Decompression::clear()
   {
   zeroise(buffer);

   no_writes = true;

   if(lzma)
      {
      lzma_end(&(lzma->stream));
      delete lzma;
      lzma = 0;
      }
   }

}
