/*
* Reader of /dev/random and company
* (C) 1999-2009,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/dev_random.h>
#include <botan/exceptn.h>

#include <sys/types.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
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

   m_max_fd = 0;

   for(auto fsname : fsnames)
      {
      int fd = ::open(fsname.c_str(), flags);

      if(fd < 0)
         {
         /*
         ENOENT or EACCES is normal as some of the named devices may not exist
         on this system. But any other errno value probably indicates
         either a bug in the application or file descriptor exhaustion.
         */
         if(errno != ENOENT && errno != EACCES)
            throw System_Error("Opening OS RNG device failed", errno);
         }
      else
         {
         if(fd > FD_SETSIZE)
            {
            ::close(fd);
            throw Invalid_State("Open of OS RNG succeeded but returned fd is too large for fd_set");
            }

         m_dev_fds.push_back(fd);
         m_max_fd = std::max(m_max_fd, fd);
         }
      }
   }

/**
Device_EntropySource destructor: close all open devices
*/
Device_EntropySource::~Device_EntropySource()
   {
   for(int fd : m_dev_fds)
      {
      // ignoring return value here, can't throw in destructor anyway
      ::close(fd);
      }
   }

/**
* Gather entropy from a RNG device
*/
size_t Device_EntropySource::poll(RandomNumberGenerator& rng)
   {
   size_t bits = 0;

   if(m_dev_fds.size() > 0)
      {
      fd_set read_set;
      FD_ZERO(&read_set);

      for(int dev_fd : m_dev_fds)
         {
         FD_SET(dev_fd, &read_set);
         }

      secure_vector<uint8_t> io_buf(BOTAN_SYSTEM_RNG_POLL_REQUEST);

      struct ::timeval timeout;
      timeout.tv_sec = (BOTAN_SYSTEM_RNG_POLL_TIMEOUT_MS / 1000);
      timeout.tv_usec = (BOTAN_SYSTEM_RNG_POLL_TIMEOUT_MS % 1000) * 1000;

      if(::select(m_max_fd + 1, &read_set, nullptr, nullptr, &timeout) > 0)
         {
         for(int dev_fd : m_dev_fds)
            {
            if(FD_ISSET(dev_fd, &read_set))
               {
               const ssize_t got = ::read(dev_fd, io_buf.data(), io_buf.size());

               if(got > 0)
                  {
                  rng.add_entropy(io_buf.data(), static_cast<size_t>(got));
                  bits += got * 8;
                  }
               }
            }
         }
      }

   return bits;
   }

}
