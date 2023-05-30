/*
* Pipe I/O for Unix
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pipe.h>

#include <botan/exceptn.h>
#include <unistd.h>

namespace Botan {

/*
* Write data from a pipe into a Unix fd
*/
int operator<<(int fd, Pipe& pipe) {
   secure_vector<uint8_t> buffer(BOTAN_DEFAULT_BUFFER_SIZE);
   while(pipe.remaining()) {
      size_t got = pipe.read(buffer.data(), buffer.size());
      size_t position = 0;
      while(got) {
         ssize_t ret = ::write(fd, &buffer[position], got);
         if(ret < 0) {
            throw Stream_IO_Error("Pipe output operator (unixfd) has failed");
         }

         position += static_cast<size_t>(ret);
         got -= static_cast<size_t>(ret);
      }
   }
   return fd;
}

/*
* Read data from a Unix fd into a pipe
*/
int operator>>(int fd, Pipe& pipe) {
   secure_vector<uint8_t> buffer(BOTAN_DEFAULT_BUFFER_SIZE);
   while(true) {
      ssize_t ret = ::read(fd, buffer.data(), buffer.size());
      if(ret < 0) {
         throw Stream_IO_Error("Pipe input operator (unixfd) has failed");
      } else if(ret == 0) {
         break;
      }
      pipe.write(buffer.data(), static_cast<size_t>(ret));
   }
   return fd;
}

}  // namespace Botan
