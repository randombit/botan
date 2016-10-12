/*
* EGD EntropySource
* (C) 1999-2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/es_egd.h>
#include <botan/parsing.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>

#ifndef PF_LOCAL
  #define PF_LOCAL PF_UNIX
#endif

namespace Botan {

EGD_EntropySource::EGD_Socket::EGD_Socket(const std::string& path) :
   m_socket_path(path), m_fd(-1)
   {
   }

/**
* Attempt a connection to an EGD/PRNGD socket
*/
int EGD_EntropySource::EGD_Socket::open_socket(const std::string& path)
   {
   int fd = ::socket(PF_LOCAL, SOCK_STREAM, 0);

   if(fd >= 0)
      {
      sockaddr_un addr;
      clear_mem(&addr, 1);
      addr.sun_family = PF_LOCAL;

      if(path.length() >= sizeof(addr.sun_path))
         throw Invalid_Argument("EGD socket path is too long");

      std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path));

      int len = sizeof(addr.sun_family) + std::strlen(addr.sun_path) + 1;

      if(::connect(fd, reinterpret_cast<struct ::sockaddr*>(&addr), len) < 0)
         {
         ::close(fd);
         fd = -1;
         }
      }

   return fd;
   }

/**
* Attempt to read entropy from EGD
*/
size_t EGD_EntropySource::EGD_Socket::read(byte outbuf[], size_t length)
   {
   if(length == 0)
      return 0;

   if(m_fd < 0)
      {
      m_fd = open_socket(m_socket_path);
      if(m_fd < 0)
         return 0;
      }

   try
      {
      // 1 == EGD command for non-blocking read
      byte egd_read_command[2] = {
         1, static_cast<byte>(std::min<size_t>(length, 255)) };

      if(::write(m_fd, egd_read_command, 2) != 2)
         throw Exception("Writing entropy read command to EGD failed");

      byte out_len = 0;
      if(::read(m_fd, &out_len, 1) != 1)
         throw Exception("Reading response length from EGD failed");

      if(out_len > egd_read_command[1])
         throw Exception("Bogus length field received from EGD");

      ssize_t count = ::read(m_fd, outbuf, out_len);

      if(count != out_len)
         throw Exception("Reading entropy result from EGD failed");

      return static_cast<size_t>(count);
      }
   catch(std::exception)
      {
      this->close();
      // Will attempt to reopen next poll
      }

   return 0;
   }

void EGD_EntropySource::EGD_Socket::close()
   {
   if(m_fd >= 0)
      {
      ::close(m_fd);
      m_fd = -1;
      }
   }

/**
* EGD_EntropySource constructor
*/
EGD_EntropySource::EGD_EntropySource(const std::vector<std::string>& paths)
   {
   for(size_t i = 0; i != paths.size(); ++i)
      m_sockets.push_back(EGD_Socket(paths[i]));
   }

EGD_EntropySource::~EGD_EntropySource()
   {
   for(size_t i = 0; i != m_sockets.size(); ++i)
      m_sockets[i].close();
   m_sockets.clear();
   }

/**
* Gather Entropy from EGD
*/
size_t EGD_EntropySource::poll(RandomNumberGenerator& rng)
   {
   lock_guard_type<mutex_type> lock(m_mutex);

   secure_vector<byte> buf(BOTAN_SYSTEM_RNG_POLL_REQUEST);

   for(size_t i = 0; i != m_sockets.size(); ++i)
      {
      size_t got = m_sockets[i].read(m_io_buf.data(), m_io_buf.size());

      if(got)
         {
         rng.add_entropy(m_io_buf.data(), got);
         return got * 8;
         }
      }

   return 0;
   }

}
