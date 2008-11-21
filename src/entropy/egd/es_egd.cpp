/**
* EGD EntropySource Source File
* (C) 1999-2008 Jack Lloyd
*/

#include <botan/es_egd.h>
#include <botan/bit_ops.h>
#include <botan/parsing.h>
#include <botan/exceptn.h>
#include <cstring>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef PF_LOCAL
  #define PF_LOCAL PF_UNIX
#endif

namespace Botan {

EGD_EntropySource::EGD_Socket::EGD_Socket(const std::string& path)
   {
   m_fd = ::socket(PF_LOCAL, SOCK_STREAM, 0);

   if(m_fd > 0)
      {
      sockaddr_un addr;
      std::memset(&addr, 0, sizeof(addr));
      addr.sun_family = PF_LOCAL;

      if(sizeof(addr.sun_path) < path.length() + 1)
         throw Exception("EGD_EntropySource: Socket path is too long");
      std::strcpy(addr.sun_path, path.c_str());

      int len = sizeof(addr.sun_family) + std::strlen(addr.sun_path) + 1;

      if(::connect(m_fd, reinterpret_cast<struct ::sockaddr*>(&addr), len) < 0)
         {
         ::close(m_fd);
         m_fd = -1;
         }
      }
   }

void EGD_EntropySource::EGD_Socket::close()
   {
   if(m_fd > 0)
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
      {
      EGD_Socket sock(paths[i]);

      if(sock.fd() != -1)
         sockets.push_back(sock);
      }
   }

EGD_EntropySource::~EGD_EntropySource()
   {
   for(size_t i = 0; i != sockets.size(); ++i)
      sockets[i].close();
   sockets.clear();
   }

/**
* Gather Entropy from EGD
*/
u32bit EGD_EntropySource::slow_poll(byte output[], u32bit length)
   {
   if(length > 128)
      length = 128;

   for(size_t i = 0; i != sockets.size(); ++i)
      {
      EGD_Socket& socket = sockets[i];

      byte buffer[2];
      buffer[0] = 1;
      buffer[1] = static_cast<byte>(length);

      if(::write(socket.fd(), buffer, 2) != 2)
         return 0;

      byte out_len = 0;
      if(::read(socket.fd(), &out_len, 1) != 1)
         return 0;

      if(out_len > length)
         return 0;

      ssize_t count = ::read(socket.fd(), output, out_len);

      if(count < 0)
         return 0;
      }

   return 0;
   }

/**
* Gather Entropy from EGD, limiting to 64 bytes
*/
u32bit EGD_EntropySource::fast_poll(byte output[], u32bit length)
   {
   return slow_poll(output, std::min<u32bit>(length, 64));
   }

}
