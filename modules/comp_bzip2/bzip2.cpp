/*************************************************
* Bzip Compressor Source File                    *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/bzip2.h>
#include <map>
#include <cstring>
#define BZ_NO_STDIO
#include <bzlib.h>

namespace Botan {

namespace {

/*************************************************
* Allocation Information for Bzip                *
*************************************************/
class Bzip_Alloc_Info
   {
   public:
      std::map<void*, u32bit> current_allocs;
      Allocator* alloc;

      Bzip_Alloc_Info() { alloc = Allocator::get(false); }
   };

/*************************************************
* Allocation Function for Bzip                   *
*************************************************/
void* bzip_malloc(void* info_ptr, int n, int size)
   {
   Bzip_Alloc_Info* info = static_cast<Bzip_Alloc_Info*>(info_ptr);
   void* ptr = info->alloc->allocate(n * size);
   info->current_allocs[ptr] = n * size;
   return ptr;
   }

/*************************************************
* Allocation Function for Bzip                   *
*************************************************/
void bzip_free(void* info_ptr, void* ptr)
   {
   Bzip_Alloc_Info* info = static_cast<Bzip_Alloc_Info*>(info_ptr);
   std::map<void*, u32bit>::const_iterator i = info->current_allocs.find(ptr);
   if(i == info->current_allocs.end())
      throw Invalid_Argument("bzip_free: Got pointer not allocated by us");
   info->alloc->deallocate(ptr, i->second);
   }

}

/*************************************************
* Wrapper Type for Bzip2 Stream                  *
*************************************************/
class Bzip_Stream
   {
   public:
      bz_stream stream;

      Bzip_Stream()
         {
         std::memset(&stream, 0, sizeof(bz_stream));
         stream.bzalloc = bzip_malloc;
         stream.bzfree = bzip_free;
         stream.opaque = new Bzip_Alloc_Info;
         }
      ~Bzip_Stream()
         {
         Bzip_Alloc_Info* info = static_cast<Bzip_Alloc_Info*>(stream.opaque);
         delete info;
         std::memset(&stream, 0, sizeof(bz_stream));
         }
   };

/*************************************************
* Bzip_Compression Constructor                   *
*************************************************/
Bzip_Compression::Bzip_Compression(u32bit l) :
   level((l >= 9) ? 9 : l), buffer(DEFAULT_BUFFERSIZE)
   {
   bz = 0;
   }

/*************************************************
* Start Compressing with Bzip                    *
*************************************************/
void Bzip_Compression::start_msg()
   {
   clear();
   bz = new Bzip_Stream;
   if(BZ2_bzCompressInit(&(bz->stream), level, 0, 0) != BZ_OK)
      throw Exception("Bzip_Compression: Memory allocation error");
   }

/*************************************************
* Compress Input with Bzip                       *
*************************************************/
void Bzip_Compression::write(const byte input[], u32bit length)
   {
   bz->stream.next_in = (char*)input;
   bz->stream.avail_in = length;

   while(bz->stream.avail_in != 0)
      {
      bz->stream.next_out = (char*)buffer.begin();
      bz->stream.avail_out = buffer.size();
      BZ2_bzCompress(&(bz->stream), BZ_RUN);
      send(buffer, buffer.size() - bz->stream.avail_out);
      }
   }

/*************************************************
* Finish Compressing with Bzip                   *
*************************************************/
void Bzip_Compression::end_msg()
   {
   bz->stream.next_in = 0;
   bz->stream.avail_in = 0;

   int rc = BZ_OK;
   while(rc != BZ_STREAM_END)
      {
      bz->stream.next_out = (char*)buffer.begin();
      bz->stream.avail_out = buffer.size();
      rc = BZ2_bzCompress(&(bz->stream), BZ_FINISH);
      send(buffer, buffer.size() - bz->stream.avail_out);
      }
   clear();
   }

/*************************************************
* Flush the Bzip Compressor                      *
*************************************************/
void Bzip_Compression::flush()
   {
   bz->stream.next_in = 0;
   bz->stream.avail_in = 0;

   int rc = BZ_OK;
   while(rc != BZ_RUN_OK)
      {
      bz->stream.next_out = (char*)buffer.begin();
      bz->stream.avail_out = buffer.size();
      rc = BZ2_bzCompress(&(bz->stream), BZ_FLUSH);
      send(buffer, buffer.size() - bz->stream.avail_out);
      }
   }

/*************************************************
* Clean up Compression Context                   *
*************************************************/
void Bzip_Compression::clear()
   {
   if(!bz) return;
   BZ2_bzCompressEnd(&(bz->stream));
   delete bz;
   bz = 0;
   }

/*************************************************
* Bzip_Decompression Constructor                 *
*************************************************/
Bzip_Decompression::Bzip_Decompression(bool s) :
   small_mem(s), buffer(DEFAULT_BUFFERSIZE)
   {
   no_writes = true;
   bz = 0;
   }

/*************************************************
* Decompress Input with Bzip                     *
*************************************************/
void Bzip_Decompression::write(const byte input[], u32bit length)
   {
   if(length) no_writes = false;
   bz->stream.next_in = (char*)input;
   bz->stream.avail_in = length;

   while(bz->stream.avail_in != 0)
      {
      bz->stream.next_out = (char*)buffer.begin();
      bz->stream.avail_out = buffer.size();

      int rc = BZ2_bzDecompress(&(bz->stream));
      if(rc != BZ_OK && rc != BZ_STREAM_END)
         {
         clear();
         if(rc == BZ_DATA_ERROR)
            throw Decoding_Error("Bzip_Decompression: Data integrity error");
         if(rc == BZ_DATA_ERROR_MAGIC)
            throw Decoding_Error("Bzip_Decompression: Invalid input");
         if(rc == BZ_MEM_ERROR)
            throw Exception("Bzip_Decompression: Memory allocation error");
         throw Exception("Bzip_Decompression: Unknown decompress error");
         }
      send(buffer, buffer.size() - bz->stream.avail_out);
      if(rc == BZ_STREAM_END)
         {
         u32bit read_from_block = length - bz->stream.avail_in;
         start_msg();
         bz->stream.next_in = (char*)input + read_from_block;
         bz->stream.avail_in = length - read_from_block;
         input += read_from_block;
         length -= read_from_block;
         }
      }
   }

/*************************************************
* Start Decompressing with Bzip                  *
*************************************************/
void Bzip_Decompression::start_msg()
   {
   clear();
   bz = new Bzip_Stream;
   if(BZ2_bzDecompressInit(&(bz->stream), 0, small_mem) != BZ_OK)
      throw Exception("Bzip_Decompression: Memory allocation error");
   no_writes = true;
   }

/*************************************************
* Finish Decompressing with Bzip                 *
*************************************************/
void Bzip_Decompression::end_msg()
   {
   if(no_writes) return;
   bz->stream.next_in = 0;
   bz->stream.avail_in = 0;

   int rc = BZ_OK;
   while(rc != BZ_STREAM_END)
      {
      bz->stream.next_out = (char*)buffer.begin();
      bz->stream.avail_out = buffer.size();
      rc = BZ2_bzDecompress(&(bz->stream));
      if(rc != BZ_OK && rc != BZ_STREAM_END)
         {
         clear();
         throw Exception("Bzip_Decompression: Error finalizing decompression");
         }
      send(buffer, buffer.size() - bz->stream.avail_out);
      }
   clear();
   }

/*************************************************
* Clean up Decompression Context                 *
*************************************************/
void Bzip_Decompression::clear()
   {
   if(!bz) return;
   BZ2_bzDecompressEnd(&(bz->stream));
   delete bz;
   bz = 0;
   }

}
