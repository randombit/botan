/*
* Reader of /dev/random and company
* (C) 1999-2009,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/dev_random.h>

#include <sys/types.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

namespace Botan {

/**
Device_EntropySource constructor
Open a file descriptor to each (available) device in fsnames
*/
Device_EntropySource::Device_EntropySource(const std::vector<std::string>& fsnames)
   {
#ifndef O_NONBLOCK
  #define O_NONBLOCK 0
#endif

#ifndef O_NOCTTY
  #define O_NOCTTY 0
#endif

   const int flags = O_RDONLY | O_NONBLOCK | O_NOCTTY;

   for(auto fsname : fsnames)
      {
      fd_type fd = ::open(fsname.c_str(), flags);

      if(fd >= 0 && fd < FD_SETSIZE)
         m_devices.push_back(fd);
      else if(fd >= 0)
         ::close(fd);
      }
   }

/**
Device_EntropySource destructor: close all open devices
*/
Device_EntropySource::~Device_EntropySource()
   {
   for(size_t i = 0; i != m_devices.size(); ++i)
      ::close(m_devices[i]);
   }

/**
* Gather entropy from a RNG device
*/
void Device_EntropySource::poll(Entropy_Accumulator& accum)
   {
   if(m_devices.empty())
      return;

   const size_t ENTROPY_BITS_PER_BYTE = 8;

   fd_type max_fd = m_devices[0];
   fd_set read_set;
   FD_ZERO(&read_set);
   for(size_t i = 0; i != m_devices.size(); ++i)
      {
      FD_SET(m_devices[i], &read_set);
      max_fd = std::max(m_devices[i], max_fd);
      }

   struct ::timeval timeout;

   timeout.tv_sec = (BOTAN_SYSTEM_RNG_POLL_TIMEOUT_MS / 1000);
   timeout.tv_usec = (BOTAN_SYSTEM_RNG_POLL_TIMEOUT_MS % 1000) * 1000;

   if(::select(max_fd + 1, &read_set, nullptr, nullptr, &timeout) < 0)
      return;

   secure_vector<byte>& buf = accum.get_io_buf(BOTAN_SYSTEM_RNG_POLL_REQUEST);

   for(size_t i = 0; i != m_devices.size(); ++i)
      {
      if(FD_ISSET(m_devices[i], &read_set))
         {
         const ssize_t got = ::read(m_devices[i], buf.data(), buf.size());
         if(got > 0)
            accum.add(buf.data(), got, ENTROPY_BITS_PER_BYTE);
         }
      }
   }

}
