/*************************************************
* Zlib Compressor Source File                    *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/zlib.h>
#include <cstring>
#include <map>
#include <zlib.h>

namespace Botan {

namespace {

/*************************************************
* Allocation Information for Zlib                *
*************************************************/
class Zlib_Alloc_Info
   {
   public:
      std::map<void*, u32bit> current_allocs;
      Allocator* alloc;

      Zlib_Alloc_Info() { alloc = Allocator::get(false); }
   };

/*************************************************
* Allocation Function for Zlib                   *
*************************************************/
void* zlib_malloc(void* info_ptr, unsigned int n, unsigned int size)
   {
   Zlib_Alloc_Info* info = static_cast<Zlib_Alloc_Info*>(info_ptr);
   void* ptr = info->alloc->allocate(n * size);
   info->current_allocs[ptr] = n * size;
   return ptr;
   }

/*************************************************
* Allocation Function for Zlib                   *
*************************************************/
void zlib_free(void* info_ptr, void* ptr)
   {
   Zlib_Alloc_Info* info = static_cast<Zlib_Alloc_Info*>(info_ptr);
   std::map<void*, u32bit>::const_iterator i = info->current_allocs.find(ptr);
   if(i == info->current_allocs.end())
      throw Invalid_Argument("zlib_free: Got pointer not allocated by us");
   info->alloc->deallocate(ptr, i->second);
   }

}

/*************************************************
* Wrapper Type for Zlib z_stream                 *
*************************************************/
class Zlib_Stream
   {
   public:
      z_stream stream;

      Zlib_Stream()
         {
         std::memset(&stream, 0, sizeof(z_stream));
         stream.zalloc = zlib_malloc;
         stream.zfree = zlib_free;
         stream.opaque = new Zlib_Alloc_Info;
         }
      ~Zlib_Stream()
         {
         Zlib_Alloc_Info* info = static_cast<Zlib_Alloc_Info*>(stream.opaque);
         delete info;
         std::memset(&stream, 0, sizeof(z_stream));
         }
   };

/*************************************************
* Zlib_Compression Constructor                   *
*************************************************/
Zlib_Compression::Zlib_Compression(u32bit l) :
   level((l >= 9) ? 9 : l), buffer(DEFAULT_BUFFERSIZE)
   {
   zlib = 0;
   }

/*************************************************
* Start Compressing with Zlib                    *
*************************************************/
void Zlib_Compression::start_msg()
   {
   clear();
   zlib = new Zlib_Stream;
   if(deflateInit(&(zlib->stream), level) != Z_OK)
      throw Exception("Zlib_Compression: Memory allocation error");
   }

/*************************************************
* Compress Input with Zlib                       *
*************************************************/
void Zlib_Compression::write(const byte input[], u32bit length)
   {
   zlib->stream.next_in = (Bytef*)input;
   zlib->stream.avail_in = length;

   while(zlib->stream.avail_in != 0)
      {
      zlib->stream.next_out = (Bytef*)buffer.begin();
      zlib->stream.avail_out = buffer.size();
      deflate(&(zlib->stream), Z_NO_FLUSH);
      send(buffer.begin(), buffer.size() - zlib->stream.avail_out);
      }
   }

/*************************************************
* Finish Compressing with Zlib                   *
*************************************************/
void Zlib_Compression::end_msg()
   {
   zlib->stream.next_in = 0;
   zlib->stream.avail_in = 0;

   int rc = Z_OK;
   while(rc != Z_STREAM_END)
      {
      zlib->stream.next_out = (Bytef*)buffer.begin();
      zlib->stream.avail_out = buffer.size();
      rc = deflate(&(zlib->stream), Z_FINISH);
      send(buffer.begin(), buffer.size() - zlib->stream.avail_out);
      }
   clear();
   }

/*************************************************
* Flush the Zlib Compressor                      *
*************************************************/
void Zlib_Compression::flush()
   {
   zlib->stream.next_in = 0;
   zlib->stream.avail_in = 0;

   while(true)
      {
      zlib->stream.next_out = (Bytef*)buffer.begin();
      zlib->stream.avail_out = buffer.size();
      deflate(&(zlib->stream), Z_FULL_FLUSH);
      send(buffer.begin(), buffer.size() - zlib->stream.avail_out);
      if(zlib->stream.avail_out == buffer.size()) break;
      }
   }

/*************************************************
* Clean up Compression Context                   *
*************************************************/
void Zlib_Compression::clear()
   {
   if(zlib)
      {
      deflateEnd(&(zlib->stream));
      delete zlib;
      zlib = 0;
      }

   buffer.clear();
   }

/*************************************************
* Zlib_Decompression Constructor                 *
*************************************************/
Zlib_Decompression::Zlib_Decompression() : buffer(DEFAULT_BUFFERSIZE)
   {
   zlib = 0;
   no_writes = true;
   }

/*************************************************
* Start Decompressing with Zlib                  *
*************************************************/
void Zlib_Decompression::start_msg()
   {
   clear();
   zlib = new Zlib_Stream;
   if(inflateInit(&(zlib->stream)) != Z_OK)
      throw Exception("Zlib_Decompression: Memory allocation error");
   }

/*************************************************
* Decompress Input with Zlib                     *
*************************************************/
void Zlib_Decompression::write(const byte input[], u32bit length)
   {
   if(length) no_writes = false;

   zlib->stream.next_in = (Bytef*)input;
   zlib->stream.avail_in = length;

   while(zlib->stream.avail_in != 0)
      {
      zlib->stream.next_out = (Bytef*)buffer.begin();
      zlib->stream.avail_out = buffer.size();

      int rc = inflate(&(zlib->stream), Z_SYNC_FLUSH);
      if(rc != Z_OK && rc != Z_STREAM_END)
         {
         clear();
         if(rc == Z_DATA_ERROR)
            throw Decoding_Error("Zlib_Decompression: Data integrity error");
         if(rc == Z_NEED_DICT)
            throw Decoding_Error("Zlib_Decompression: Need preset dictionary");
         if(rc == Z_MEM_ERROR)
            throw Exception("Zlib_Decompression: Memory allocation error");
         throw Exception("Zlib_Decompression: Unknown decompress error");
         }
      send(buffer.begin(), buffer.size() - zlib->stream.avail_out);
      if(rc == Z_STREAM_END)
         {
         u32bit read_from_block = length - zlib->stream.avail_in;
         start_msg();
         zlib->stream.next_in = (Bytef*)input + read_from_block;
         zlib->stream.avail_in = length - read_from_block;
         input += read_from_block;
         length -= read_from_block;
         }
      }
   }

/*************************************************
* Finish Decompressing with Zlib                 *
*************************************************/
void Zlib_Decompression::end_msg()
   {
   if(no_writes) return;
   zlib->stream.next_in = 0;
   zlib->stream.avail_in = 0;

   int rc = Z_OK;
   while(rc != Z_STREAM_END)
      {
      zlib->stream.next_out = (Bytef*)buffer.begin();
      zlib->stream.avail_out = buffer.size();
      rc = inflate(&(zlib->stream), Z_SYNC_FLUSH);
      if(rc != Z_OK && rc != Z_STREAM_END)
         {
         clear();
         throw Exception("Zlib_Decompression: Error finalizing decompression");
         }
      send(buffer.begin(), buffer.size() - zlib->stream.avail_out);
      }
   clear();
   }

/*************************************************
* Clean up Decompression Context                 *
*************************************************/
void Zlib_Decompression::clear()
   {
   no_writes = true;

   if(zlib)
      {
      inflateEnd(&(zlib->stream));
      delete zlib;
      zlib = 0;
      }

   buffer.clear();
   }

}
