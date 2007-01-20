/*************************************************
* Pipe I/O Source File                           *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/pipe.h>
#include <iostream>

namespace Botan {

/*************************************************
* Write data from a pipe into an ostream         *
*************************************************/
std::ostream& operator<<(std::ostream& stream, Pipe& pipe)
   {
   SecureVector<byte> buffer(DEFAULT_BUFFERSIZE);
   while(stream.good() && pipe.remaining())
      {
      u32bit got = pipe.read(buffer, buffer.size());
      stream.write((const char*)buffer.begin(), got);
      }
   if(!stream.good())
      throw Stream_IO_Error("Pipe output operator (iostream) has failed");
   return stream;
   }

/*************************************************
* Read data from an istream into a pipe          *
*************************************************/
std::istream& operator>>(std::istream& stream, Pipe& pipe)
   {
   SecureVector<byte> buffer(DEFAULT_BUFFERSIZE);
   while(stream.good())
      {
      stream.read((char*)buffer.begin(), buffer.size());
      pipe.write(buffer, stream.gcount());
      }
   if(stream.bad() || (stream.fail() && !stream.eof()))
      throw Stream_IO_Error("Pipe input operator (iostream) has failed");
   return stream;
   }

}
