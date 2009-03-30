/*
* Pipe I/O for Unix
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pipe.h>
#include <botan/exceptn.h>
#include <unistd.h>

namespace Botan {

/*
* Write data from a pipe into a Unix fd
*/
int operator<<(int fd, Pipe& pipe)
   {
   SecureVector<byte> buffer(DEFAULT_BUFFERSIZE);
   while(pipe.remaining())
      {
      u32bit got = pipe.read(buffer, buffer.size());
      u32bit position = 0;
      while(got)
         {
         ssize_t ret = write(fd, buffer + position, got);
         if(ret == -1)
            throw Stream_IO_Error("Pipe output operator (unixfd) has failed");
         position += ret;
         got -= ret;
         }
      }
   return fd;
   }

/*
* Read data from a Unix fd into a pipe
*/
int operator>>(int fd, Pipe& pipe)
   {
   SecureVector<byte> buffer(DEFAULT_BUFFERSIZE);
   while(true)
      {
      ssize_t ret = read(fd, buffer, buffer.size());
      if(ret == 0) break;
      if(ret == -1)
         throw Stream_IO_Error("Pipe input operator (unixfd) has failed");
      pipe.write(buffer, ret);
      }
   return fd;
   }

}
