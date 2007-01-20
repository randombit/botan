/*************************************************
* DataSource Source File                         *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/data_src.h>
#include <fstream>
#include <algorithm>

namespace Botan {

/*************************************************
* Read a single byte from the DataSource         *
*************************************************/
u32bit DataSource::read_byte(byte& out)
   {
   return read(&out, 1);
   }

/*************************************************
* Peek a single byte from the DataSource         *
*************************************************/
u32bit DataSource::peek_byte(byte& out) const
   {
   return peek(&out, 1, 0);
   }

/*************************************************
* Discard the next N bytes of the data           *
*************************************************/
u32bit DataSource::discard_next(u32bit n)
   {
   u32bit discarded = 0;
   byte dummy;
   for(u32bit j = 0; j != n; ++j)
      discarded = read_byte(dummy);
   return discarded;
   }

/*************************************************
* Read from a memory buffer                      *
*************************************************/
u32bit DataSource_Memory::read(byte out[], u32bit length)
   {
   u32bit got = std::min(source.size() - offset, length);
   copy_mem(out, source + offset, got);
   offset += got;
   return got;
   }

/*************************************************
* Peek into a memory buffer                      *
*************************************************/
u32bit DataSource_Memory::peek(byte out[], u32bit length,
                               u32bit peek_offset) const
   {
   const u32bit bytes_left = source.size() - offset;
   if(peek_offset >= bytes_left) return 0;

   u32bit got = std::min(bytes_left - peek_offset, length);
   copy_mem(out, source + offset + peek_offset, got);
   return got;
   }

/*************************************************
* Check if the memory buffer is empty            *
*************************************************/
bool DataSource_Memory::end_of_data() const
   {
   return (offset == source.size());
   }

/*************************************************
* DataSource_Memory Constructor                  *
*************************************************/
DataSource_Memory::DataSource_Memory(const byte in[], u32bit length)
   {
   source.set(in, length);
   offset = 0;
   }

/*************************************************
* DataSource_Memory Constructor                  *
*************************************************/
DataSource_Memory::DataSource_Memory(const MemoryRegion<byte>& in)
   {
   source = in;
   offset = 0;
   }

/*************************************************
* DataSource_Memory Constructor                  *
*************************************************/
DataSource_Memory::DataSource_Memory(const std::string& in)
   {
   source.set((const byte*)in.c_str(), in.length());
   offset = 0;
   }

/*************************************************
* Read from a stream                             *
*************************************************/
u32bit DataSource_Stream::read(byte out[], u32bit length)
   {
   source->read((char*)out, length);
   if(source->bad())
      throw Stream_IO_Error("DataSource_Stream::read: Source failure");

   u32bit got = source->gcount();
   total_read += got;
   return (u32bit)got;
   }

/*************************************************
* Peek into a stream                             *
*************************************************/
u32bit DataSource_Stream::peek(byte out[], u32bit length, u32bit offset) const
   {
   if(end_of_data())
      throw Invalid_State("DataSource_Stream: Cannot peek when out of data");

   u32bit got = 0;

   if(offset)
      {
      SecureVector<byte> buf(offset);
      source->read((char*)buf.begin(), buf.size());
      if(source->bad())
         throw Stream_IO_Error("DataSource_Stream::peek: Source failure");
      got = source->gcount();
      }

   if(got == offset)
      {
      source->read((char*)out, length);
      if(source->bad())
         throw Stream_IO_Error("DataSource_Stream::peek: Source failure");
      got = source->gcount();
      }

   if(source->eof())
      source->clear();
   source->seekg(total_read, std::ios::beg);

   return got;
   }

/*************************************************
* Check if the stream is empty or in error       *
*************************************************/
bool DataSource_Stream::end_of_data() const
   {
   return (!source->good());
   }

/*************************************************
* Return a human-readable ID for this stream     *
*************************************************/
std::string DataSource_Stream::id() const
   {
   return fsname;
   }

/*************************************************
* DataSource_Stream Constructor                  *
*************************************************/
DataSource_Stream::DataSource_Stream(const std::string& file,
                                     bool use_binary) : fsname(file)
   {
   if(use_binary)
      source = new std::ifstream(fsname.c_str(), std::ios::binary);
   else
      source = new std::ifstream(fsname.c_str());

   if(!source->good())
      throw Stream_IO_Error("DataSource_Stream: Failure opening " + fsname);
   total_read = 0;
   }

/*************************************************
* DataSource_Stream Destructor                   *
*************************************************/
DataSource_Stream::~DataSource_Stream()
   {
   delete source;
   }

}
