/*
* Reader of /dev/random and company
* (C) 1999-2009,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/dev_random.h>

#include <sys/types.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

namespace Botan {

namespace {

int open_nonblocking(const char* pathname)
   {
#ifndef O_NONBLOCK
  #define O_NONBLOCK 0
#endif

#ifndef O_NOCTTY
  #define O_NOCTTY 0
#endif

   const int flags = O_RDONLY | O_NONBLOCK | O_NOCTTY;
   return ::open(pathname, flags);
   }

}

/**
Device_EntropySource constructor
Open a file descriptor to each (available) device in fsnames
*/
Device_EntropySource::Device_EntropySource(const std::vector<std::string>& fsnames)
   {
   for(size_t i = 0; i != fsnames.size(); ++i)
      {
      fd_type fd = open_nonblocking(fsnames[i].c_str());
      if(fd >= 0 && fd < FD_SETSIZE)
         devices.push_back(fd);
      }
   }

/**
Device_EntropySource destructor: close all open devices
*/
Device_EntropySource::~Device_EntropySource()
   {
   for(size_t i = 0; i != devices.size(); ++i)
      ::close(devices[i]);
   }

/**
* Gather entropy from a RNG device
*/
void Device_EntropySource::poll(Entropy_Accumulator& accum)
   {
   if(devices.empty())
      return;

   const size_t ENTROPY_BITS_PER_BYTE = 8;
   const size_t MS_WAIT_TIME = 32;
   const size_t READ_ATTEMPT = accum.desired_remaining_bits() / 4;

   secure_vector<byte>& io_buffer = accum.get_io_buffer(READ_ATTEMPT);

   int max_fd = devices[0];
   fd_set read_set;
   FD_ZERO(&read_set);
   for(size_t i = 0; i != devices.size(); ++i)
      {
      FD_SET(devices[i], &read_set);
      max_fd = std::max(devices[i], max_fd);
      }

   struct ::timeval timeout;

   timeout.tv_sec = (MS_WAIT_TIME / 1000);
   timeout.tv_usec = (MS_WAIT_TIME % 1000) * 1000;

   if(::select(max_fd + 1, &read_set, 0, 0, &timeout) < 0)
      return;

   for(size_t i = 0; i != devices.size(); ++i)
      {
      if(FD_ISSET(devices[i], &read_set))
         {
         const ssize_t got = ::read(devices[i], &io_buffer[0], io_buffer.size());
         accum.add(&io_buffer[0], got, ENTROPY_BITS_PER_BYTE);
         }
      }
   }

}
