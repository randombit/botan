/*
* Pipe I/O
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pipe.h>

#include <botan/mem_ops.h>
#include <istream>
#include <ostream>

namespace Botan {

/*
* Write data from a pipe into an ostream
*/
std::ostream& operator<<(std::ostream& stream, Pipe& pipe) {
   secure_vector<uint8_t> buffer(BOTAN_DEFAULT_BUFFER_SIZE);
   while(stream.good() && pipe.remaining()) {
      const size_t got = pipe.read(buffer.data(), buffer.size());
      stream.write(cast_uint8_ptr_to_char(buffer.data()), got);
   }
   if(!stream.good()) {
      throw Stream_IO_Error("Pipe output operator (iostream) has failed");
   }
   return stream;
}

/*
* Read data from an istream into a pipe
*/
std::istream& operator>>(std::istream& stream, Pipe& pipe) {
   secure_vector<uint8_t> buffer(BOTAN_DEFAULT_BUFFER_SIZE);
   while(stream.good()) {
      stream.read(cast_uint8_ptr_to_char(buffer.data()), buffer.size());
      const size_t got = static_cast<size_t>(stream.gcount());
      pipe.write(buffer.data(), got);
   }
   if(stream.bad() || (stream.fail() && !stream.eof())) {
      throw Stream_IO_Error("Pipe input operator (iostream) has failed");
   }
   return stream;
}

}  // namespace Botan
