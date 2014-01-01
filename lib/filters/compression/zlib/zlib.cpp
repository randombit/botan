/*
* Zlib Compressor
* (C) 2001 Peter J Jones
*     2001-2007 Jack Lloyd
*     2006 Matt Johnston
*
* Distributed under the terms of the Botan license
*/

#include <botan/zlib.h>
#include <botan/exceptn.h>

#include <cstring>
#include <cstdlib>
#include <map>
#include <zlib.h>

namespace Botan {

namespace {

/*
* Allocation Information for Zlib
*/
class Zlib_Alloc_Info
   {
   public:
      std::map<void*, size_t> current_allocs;
   };

/*
* Allocation Function for Zlib
*/
void* zlib_malloc(void* info_ptr, unsigned int n, unsigned int size)
   {
   Zlib_Alloc_Info* info = static_cast<Zlib_Alloc_Info*>(info_ptr);

   const size_t total_sz = n * size;

   void* ptr = std::malloc(total_sz);
   info->current_allocs[ptr] = total_sz;
   return ptr;
   }

/*
* Allocation Function for Zlib
*/
void zlib_free(void* info_ptr, void* ptr)
   {
   Zlib_Alloc_Info* info = static_cast<Zlib_Alloc_Info*>(info_ptr);
   auto i = info->current_allocs.find(ptr);
   if(i == info->current_allocs.end())
      throw Invalid_Argument("zlib_free: Got pointer not allocated by us");

   std::memset(ptr, 0, i->second);
   std::free(ptr);
   }

}

/**
* Wrapper Type for Zlib z_stream
*/
class Zlib_Stream
   {
   public:
      /**
      * Underlying stream
      */
      z_stream stream;

      /**
      * Constructor
      */
      Zlib_Stream()
         {
         std::memset(&stream, 0, sizeof(z_stream));
         stream.zalloc = zlib_malloc;
         stream.zfree = zlib_free;
         stream.opaque = new Zlib_Alloc_Info;
         }

      /**
      * Destructor
      */
      ~Zlib_Stream()
         {
         Zlib_Alloc_Info* info = static_cast<Zlib_Alloc_Info*>(stream.opaque);
         delete info;
         std::memset(&stream, 0, sizeof(z_stream));
         }
   };

/*
* Zlib_Compression Constructor
*/
Zlib_Compression::Zlib_Compression(size_t l, bool raw_deflate) :
   level((l >= 9) ? 9 : l),
   raw_deflate(raw_deflate),
   buffer(DEFAULT_BUFFERSIZE),
   zlib(0)
   {
   }

/*
* Start Compressing with Zlib
*/
void Zlib_Compression::start_msg()
   {
   clear();
   zlib = new Zlib_Stream;

   int res = deflateInit2(&(zlib->stream),
                          level,
                          Z_DEFLATED,
                          (raw_deflate ? -15 : 15),
                          8,
                          Z_DEFAULT_STRATEGY);

   if(res == Z_STREAM_ERROR)
      throw Invalid_Argument("Bad setting in deflateInit2");
   else if(res != Z_OK)
      throw Memory_Exhaustion();
   }

/*
* Compress Input with Zlib
*/
void Zlib_Compression::write(const byte input[], size_t length)
   {
   zlib->stream.next_in = static_cast<Bytef*>(const_cast<byte*>(input));
   zlib->stream.avail_in = length;

   while(zlib->stream.avail_in != 0)
      {
      zlib->stream.next_out = static_cast<Bytef*>(&buffer[0]);
      zlib->stream.avail_out = buffer.size();
      deflate(&(zlib->stream), Z_NO_FLUSH);
      send(&buffer[0], buffer.size() - zlib->stream.avail_out);
      }
   }

/*
* Finish Compressing with Zlib
*/
void Zlib_Compression::end_msg()
   {
   zlib->stream.next_in = 0;
   zlib->stream.avail_in = 0;

   int rc = Z_OK;
   while(rc != Z_STREAM_END)
      {
      zlib->stream.next_out = reinterpret_cast<Bytef*>(&buffer[0]);
      zlib->stream.avail_out = buffer.size();

      rc = deflate(&(zlib->stream), Z_FINISH);
      send(&buffer[0], buffer.size() - zlib->stream.avail_out);
      }

   clear();
   }

/*
* Flush the Zlib Compressor
*/
void Zlib_Compression::flush()
   {
   zlib->stream.next_in = 0;
   zlib->stream.avail_in = 0;

   while(true)
      {
      zlib->stream.avail_out = buffer.size();
      zlib->stream.next_out = reinterpret_cast<Bytef*>(&buffer[0]);

      deflate(&(zlib->stream), Z_FULL_FLUSH);
      send(&buffer[0], buffer.size() - zlib->stream.avail_out);

      if(zlib->stream.avail_out == buffer.size())
        break;
      }
   }

/*
* Clean up Compression Context
*/
void Zlib_Compression::clear()
   {
   zeroise(buffer);

   if(zlib)
      {
      deflateEnd(&(zlib->stream));
      delete zlib;
      zlib = 0;
      }
   }

/*
* Zlib_Decompression Constructor
*/
Zlib_Decompression::Zlib_Decompression(bool raw_deflate) :
   raw_deflate(raw_deflate),
   buffer(DEFAULT_BUFFERSIZE),
   zlib(0),
   no_writes(true)
   {
   }

/*
* Start Decompressing with Zlib
*/
void Zlib_Decompression::start_msg()
   {
   clear();
   zlib = new Zlib_Stream;

   if(inflateInit2(&(zlib->stream), (raw_deflate ? -15 : 15)) != Z_OK)
      throw Memory_Exhaustion();
   }

/*
* Decompress Input with Zlib
*/
void Zlib_Decompression::write(const byte input_arr[], size_t length)
   {
   if(length) no_writes = false;

   // non-const needed by zlib api :(
   Bytef* input = reinterpret_cast<Bytef*>(const_cast<byte*>(input_arr));

   zlib->stream.next_in = input;
   zlib->stream.avail_in = length;

   while(zlib->stream.avail_in != 0)
      {
      zlib->stream.next_out = reinterpret_cast<Bytef*>(&buffer[0]);
      zlib->stream.avail_out = buffer.size();

      int rc = inflate(&(zlib->stream), Z_SYNC_FLUSH);

      if(rc != Z_OK && rc != Z_STREAM_END)
         {
         clear();
         if(rc == Z_DATA_ERROR)
            throw Decoding_Error("Zlib_Decompression: Data integrity error");
         else if(rc == Z_NEED_DICT)
            throw Decoding_Error("Zlib_Decompression: Need preset dictionary");
         else if(rc == Z_MEM_ERROR)
            throw Memory_Exhaustion();
         else
            throw std::runtime_error("Zlib decompression: Unknown error");
         }

      send(&buffer[0], buffer.size() - zlib->stream.avail_out);

      if(rc == Z_STREAM_END)
         {
         size_t read_from_block = length - zlib->stream.avail_in;
         start_msg();

         zlib->stream.next_in = input + read_from_block;
         zlib->stream.avail_in = length - read_from_block;

         input += read_from_block;
         length -= read_from_block;
         }
      }
   }

/*
* Finish Decompressing with Zlib
*/
void Zlib_Decompression::end_msg()
   {
   if(no_writes) return;
   zlib->stream.next_in = 0;
   zlib->stream.avail_in = 0;

   int rc = Z_OK;

   while(rc != Z_STREAM_END)
      {
      zlib->stream.next_out = reinterpret_cast<Bytef*>(&buffer[0]);
      zlib->stream.avail_out = buffer.size();
      rc = inflate(&(zlib->stream), Z_SYNC_FLUSH);

      if(rc != Z_OK && rc != Z_STREAM_END)
         {
         clear();
         throw Decoding_Error("Zlib_Decompression: Error finalizing");
         }

      send(&buffer[0], buffer.size() - zlib->stream.avail_out);
      }

   clear();
   }

/*
* Clean up Decompression Context
*/
void Zlib_Decompression::clear()
   {
   zeroise(buffer);

   no_writes = true;

   if(zlib)
      {
      inflateEnd(&(zlib->stream));
      delete zlib;
      zlib = 0;
      }
   }

}
