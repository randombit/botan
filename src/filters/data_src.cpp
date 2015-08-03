/*
* DataSource
* (C) 1999-2007 Jack Lloyd
*     2005 Matthew Gregan
*
* Distributed under the terms of the Botan license
*/

#include <botan/data_src.h>
#include <botan/exceptn.h>
#include <fstream>
#include <algorithm>

namespace Botan {

/*
* Read a single byte from the DataSource
*/
size_t DataSource::read_byte(byte& out)
   {
   return read(&out, 1);
   }

/*
* Peek a single byte from the DataSource
*/
size_t DataSource::peek_byte(byte& out) const
   {
   return peek(&out, 1, 0);
   }

/*
* Discard the next N bytes of the data
*/
size_t DataSource::discard_next(size_t n)
   {
   size_t discarded = 0;
   byte dummy;
   for(size_t j = 0; j != n; ++j)
      discarded += read_byte(dummy);
   return discarded;
   }

/*
* Read from a memory buffer
*/
size_t DataSource_Memory::read(byte out[], size_t length)
   {
   size_t got = std::min<size_t>(source.size() - offset, length);
   copy_mem(out, &source[offset], got);
   offset += got;
   return got;
   }

/*
* Peek into a memory buffer
*/
size_t DataSource_Memory::peek(byte out[], size_t length,
                               size_t peek_offset) const
   {
   const size_t bytes_left = source.size() - offset;
   if(peek_offset >= bytes_left) return 0;

   size_t got = std::min(bytes_left - peek_offset, length);
   copy_mem(out, &source[offset + peek_offset], got);
   return got;
   }

/*
* Check if the memory buffer is empty
*/
bool DataSource_Memory::end_of_data() const
   {
   return (offset == source.size());
   }

/*
* DataSource_Memory Constructor
*/
DataSource_Memory::DataSource_Memory(const byte in[], size_t length) :
   source(in, length)
   {
   offset = 0;
   }

/*
* DataSource_Memory Constructor
*/
DataSource_Memory::DataSource_Memory(const MemoryRegion<byte>& in) :
   source(in)
   {
   offset = 0;
   }

/*
* DataSource_Memory Constructor
*/
DataSource_Memory::DataSource_Memory(const std::string& in) :
   source(reinterpret_cast<const byte*>(in.data()), in.length())
   {
   offset = 0;
   }

bool DataSource_Memory::check_available(size_t n)
   {
   return (n <= (source.size() - offset));
   }

/*
* Read from a stream
*/
size_t DataSource_Stream::read(byte out[], size_t length)
   {
   source.read(reinterpret_cast<char*>(out), length);
   if(source.bad())
      throw Stream_IO_Error("DataSource_Stream::read: Source failure");

   size_t got = source.gcount();
   total_read += got;
   return got;
   }

bool DataSource_Stream::check_available(size_t n)
   {
   const std::streampos orig_pos = source.tellg();
   source.seekg(0, std::ios::end);
   const size_t avail = source.tellg() - orig_pos;
   source.seekg(orig_pos);
   return (avail >= n);
   }

/*
* Peek into a stream
*/
size_t DataSource_Stream::peek(byte out[], size_t length, size_t offset) const
   {
   if(end_of_data())
      throw Invalid_State("DataSource_Stream: Cannot peek when out of data");

   size_t got = 0;

   if(offset)
      {
      SecureVector<byte> buf(offset);
      source.read(reinterpret_cast<char*>(&buf[0]), buf.size());
      if(source.bad())
         throw Stream_IO_Error("DataSource_Stream::peek: Source failure");
      got = source.gcount();
      }

   if(got == offset)
      {
      source.read(reinterpret_cast<char*>(out), length);
      if(source.bad())
         throw Stream_IO_Error("DataSource_Stream::peek: Source failure");
      got = source.gcount();
      }

   if(source.eof())
      source.clear();
   source.seekg(total_read, std::ios::beg);

   return got;
   }

/*
* Check if the stream is empty or in error
*/
bool DataSource_Stream::end_of_data() const
   {
   return (!source.good());
   }

/*
* Return a human-readable ID for this stream
*/
std::string DataSource_Stream::id() const
   {
   return identifier;
   }

/*
* DataSource_Stream Constructor
*/
DataSource_Stream::DataSource_Stream(const std::string& path,
                                     bool use_binary) :
   identifier(path),
   source_p(new std::ifstream(
               path.c_str(),
               use_binary ? std::ios::binary : std::ios::in)),
   source(*source_p),
   total_read(0)
   {
   if(!source.good())
      {
      delete source_p;
      throw Stream_IO_Error("DataSource: Failure opening file " + path);
      }
   }

/*
* DataSource_Stream Constructor
*/
DataSource_Stream::DataSource_Stream(std::istream& in,
                                     const std::string& name) :
   identifier(name),
   source_p(0),
   source(in),
   total_read(0)
   {
   }

/*
* DataSource_Stream Destructor
*/
DataSource_Stream::~DataSource_Stream()
   {
   delete source_p;
   }

}
