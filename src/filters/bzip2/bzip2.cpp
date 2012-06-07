/*
* Bzip Compressor
* (C) 2001 Peter J Jones
*     2001-2007 Jack Lloyd
*     2006 Matt Johnston
*
* Distributed under the terms of the Botan license
*/

#include <botan/bzip2.h>
#include <botan/exceptn.h>

#include <map>
#include <cstring>
#define BZ_NO_STDIO
#include <bzlib.h>

namespace Botan {

namespace {

/*
* Allocation Information for Bzip
*/
class Bzip_Alloc_Info
   {
   public:
      std::map<void*, size_t> current_allocs;
   };

/*
* Allocation Function for Bzip
*/
void* bzip_malloc(void* info_ptr, int n, int size)
   {
   Bzip_Alloc_Info* info = static_cast<Bzip_Alloc_Info*>(info_ptr);

   const size_t total_sz = n * size;

   void* ptr = std::malloc(total_sz);
   info->current_allocs[ptr] = total_sz;
   return ptr;
   }

/*
* Allocation Function for Bzip
*/
void bzip_free(void* info_ptr, void* ptr)
   {
   Bzip_Alloc_Info* info = static_cast<Bzip_Alloc_Info*>(info_ptr);
   auto i = info->current_allocs.find(ptr);
   if(i == info->current_allocs.end())
      throw Invalid_Argument("bzip_free: Got pointer not allocated by us");

   std::memset(ptr, 0, i->second);
   std::free(ptr);
   }

}

/**
* Wrapper Type for Bzip2 Stream
*/
class Bzip_Stream
   {
   public:
      /**
      * Underlying stream
      */
      bz_stream stream;

      /**
      * Constructor
      */
      Bzip_Stream()
         {
         std::memset(&stream, 0, sizeof(bz_stream));
         stream.bzalloc = bzip_malloc;
         stream.bzfree = bzip_free;
         stream.opaque = new Bzip_Alloc_Info;
         }

      /**
      * Destructor
      */
      ~Bzip_Stream()
         {
         Bzip_Alloc_Info* info = static_cast<Bzip_Alloc_Info*>(stream.opaque);
         delete info;
         std::memset(&stream, 0, sizeof(bz_stream));
         }
   };

/*
* Bzip_Compression Constructor
*/
Bzip_Compression::Bzip_Compression(size_t l) :
   level((l >= 9) ? 9 : l), buffer(DEFAULT_BUFFERSIZE)
   {
   bz = 0;
   }

/*
* Start Compressing with Bzip
*/
void Bzip_Compression::start_msg()
   {
   clear();
   bz = new Bzip_Stream;
   if(BZ2_bzCompressInit(&(bz->stream), level, 0, 0) != BZ_OK)
      throw Memory_Exhaustion();
   }

/*
* Compress Input with Bzip
*/
void Bzip_Compression::write(const byte input[], size_t length)
   {
   bz->stream.next_in = reinterpret_cast<char*>(const_cast<byte*>(input));
   bz->stream.avail_in = length;

   while(bz->stream.avail_in != 0)
      {
      bz->stream.next_out = reinterpret_cast<char*>(&buffer[0]);
      bz->stream.avail_out = buffer.size();
      BZ2_bzCompress(&(bz->stream), BZ_RUN);
      send(buffer, buffer.size() - bz->stream.avail_out);
      }
   }

/*
* Finish Compressing with Bzip
*/
void Bzip_Compression::end_msg()
   {
   bz->stream.next_in = 0;
   bz->stream.avail_in = 0;

   int rc = BZ_OK;
   while(rc != BZ_STREAM_END)
      {
      bz->stream.next_out = reinterpret_cast<char*>(&buffer[0]);
      bz->stream.avail_out = buffer.size();
      rc = BZ2_bzCompress(&(bz->stream), BZ_FINISH);
      send(buffer, buffer.size() - bz->stream.avail_out);
      }
   clear();
   }

/*
* Flush the Bzip Compressor
*/
void Bzip_Compression::flush()
   {
   bz->stream.next_in = 0;
   bz->stream.avail_in = 0;

   int rc = BZ_OK;
   while(rc != BZ_RUN_OK)
      {
      bz->stream.next_out = reinterpret_cast<char*>(&buffer[0]);
      bz->stream.avail_out = buffer.size();
      rc = BZ2_bzCompress(&(bz->stream), BZ_FLUSH);
      send(buffer, buffer.size() - bz->stream.avail_out);
      }
   }

/*
* Clean up Compression Context
*/
void Bzip_Compression::clear()
   {
   zeroise(buffer);

   if(bz)
      {
      BZ2_bzCompressEnd(&(bz->stream));
      delete bz;
      bz = 0;
      }
   }

/*
* Bzip_Decompression Constructor
*/
Bzip_Decompression::Bzip_Decompression(bool s) :
   small_mem(s), buffer(DEFAULT_BUFFERSIZE)
   {
   no_writes = true;
   bz = 0;
   }

/*
* Decompress Input with Bzip
*/
void Bzip_Decompression::write(const byte input_arr[], size_t length)
   {
   if(length) no_writes = false;

   char* input = reinterpret_cast<char*>(const_cast<byte*>(input_arr));

   bz->stream.next_in = input;
   bz->stream.avail_in = length;

   while(bz->stream.avail_in != 0)
      {
      bz->stream.next_out = reinterpret_cast<char*>(&buffer[0]);
      bz->stream.avail_out = buffer.size();

      int rc = BZ2_bzDecompress(&(bz->stream));

      if(rc != BZ_OK && rc != BZ_STREAM_END)
         {
         clear();

         if(rc == BZ_DATA_ERROR)
            throw Decoding_Error("Bzip_Decompression: Data integrity error");
         else if(rc == BZ_DATA_ERROR_MAGIC)
            throw Decoding_Error("Bzip_Decompression: Invalid input");
         else if(rc == BZ_MEM_ERROR)
            throw Memory_Exhaustion();
         else
            throw std::runtime_error("Bzip2 decompression: Unknown error");
         }

      send(buffer, buffer.size() - bz->stream.avail_out);

      if(rc == BZ_STREAM_END)
         {
         size_t read_from_block = length - bz->stream.avail_in;
         start_msg();
         bz->stream.next_in = input + read_from_block;
         bz->stream.avail_in = length - read_from_block;
         input += read_from_block;
         length -= read_from_block;
         }
      }
   }

/*
* Start Decompressing with Bzip
*/
void Bzip_Decompression::start_msg()
   {
   clear();
   bz = new Bzip_Stream;

   if(BZ2_bzDecompressInit(&(bz->stream), 0, small_mem) != BZ_OK)
      throw Memory_Exhaustion();

   no_writes = true;
   }

/*
* Finish Decompressing with Bzip
*/
void Bzip_Decompression::end_msg()
   {
   if(no_writes) return;
   bz->stream.next_in = 0;
   bz->stream.avail_in = 0;

   int rc = BZ_OK;
   while(rc != BZ_STREAM_END)
      {
      bz->stream.next_out = reinterpret_cast<char*>(&buffer[0]);
      bz->stream.avail_out = buffer.size();
      rc = BZ2_bzDecompress(&(bz->stream));

      if(rc != BZ_OK && rc != BZ_STREAM_END)
         {
         clear();
         throw Decoding_Error("Bzip_Decompression: Error finalizing");
         }

      send(buffer, buffer.size() - bz->stream.avail_out);
      }

   clear();
   }

/*
* Clean up Decompression Context
*/
void Bzip_Decompression::clear()
   {
   zeroise(buffer);

   if(bz)
      {
      BZ2_bzDecompressEnd(&(bz->stream));
      delete bz;
      bz = 0;
      }
   }

}
