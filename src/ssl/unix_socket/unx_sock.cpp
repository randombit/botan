/**
* Unix Socket
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/unx_sock.h>
#include <botan/exceptn.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

namespace Botan {

/**
* Unix Socket Constructor
*/
Unix_Socket::Unix_Socket(const std::string& host, u16bit port) : peer(host)
   {
   sockfd = -1;

   hostent* host_addr = ::gethostbyname(host.c_str());

   if(host_addr == 0)
      throw Stream_IO_Error("Unix_Socket: gethostbyname failed for " + host);
   if(host_addr->h_addrtype != AF_INET) // FIXME
      throw Stream_IO_Error("Unix_Socket: " + host + " has IPv6 address");

   int fd = ::socket(PF_INET, SOCK_STREAM, 0);
   if(fd == -1)
      throw Stream_IO_Error("Unix_Socket: Unable to acquire socket");

   sockaddr_in socket_info;
   ::memset(&socket_info, 0, sizeof(socket_info));
   socket_info.sin_family = AF_INET;
   socket_info.sin_port = htons(port);
   socket_info.sin_addr = *(struct in_addr*)host_addr->h_addr; // FIXME

   if(::connect(fd, (sockaddr*)&socket_info, sizeof(struct sockaddr)) != 0)
      {
      ::close(fd);
      throw Stream_IO_Error("Unix_Socket: connect failed");
      }

   sockfd = fd;
   }

/**
* Unix Socket Constructor
*/
Unix_Socket::Unix_Socket(int fd, const std::string& peer_id)
   {
   sockfd = fd;
   peer = peer_id;
   }

/**
* Read from a Unix socket
*/
u32bit Unix_Socket::read(byte buf[], u32bit length)
   {
   if(sockfd == -1)
      throw Stream_IO_Error("Unix_Socket::read: Socket not connected");

   u32bit got = 0;

   while(length)
      {
      ssize_t this_time = ::recv(sockfd, buf + got, length, MSG_NOSIGNAL);

      if(this_time == 0)
         break;

      if(this_time == -1)
         {
         if(errno == EINTR)
            this_time = 0;
         else
            throw Stream_IO_Error("Unix_Socket::read: Socket read failed");
         }

      got += this_time;
      length -= this_time;
      }
   return got;
   }

/**
* Write to a Unix socket
*/
void Unix_Socket::write(const byte buf[], u32bit length)
   {
   if(sockfd == -1)
      throw Stream_IO_Error("Unix_Socket::write: Socket not connected");

   u32bit offset = 0;
   while(length)
      {
      ssize_t sent = ::send(sockfd, buf + offset, length, MSG_NOSIGNAL);

      if(sent == -1)
         {
         if(errno == EINTR)
            sent = 0;
         else
            throw Stream_IO_Error("Unix_Socket::write: Socket write failed");
         }

      offset += sent;
      length -= sent;
      }
   }

/**
* Close a Unix socket
*/
void Unix_Socket::close()
   {
   if(sockfd != -1)
      {
      if(::close(sockfd) != 0)
         throw Stream_IO_Error("Unix_Socket::close failed");
      sockfd = -1;
      }
   }

/**
* Return the peer's name
*/
std::string Unix_Socket::peer_id() const
   {
   return peer;
   }

/**
* Unix Server Socket Constructor
*/
Unix_Server_Socket::Unix_Server_Socket(u16bit port)
   {
   sockfd = -1;

   int fd = ::socket(PF_INET, SOCK_STREAM, 0);
   if(fd == -1)
      throw Stream_IO_Error("Unix_Server_Socket: Unable to acquire socket");

   sockaddr_in socket_info;
   ::memset(&socket_info, 0, sizeof(socket_info));
   socket_info.sin_family = AF_INET;
   socket_info.sin_port = htons(port);

   // FIXME: support limiting listeners
   socket_info.sin_addr.s_addr = INADDR_ANY;

   if(::bind(fd, (sockaddr*)&socket_info, sizeof(struct sockaddr)) != 0)
      {
      ::close(fd);
      throw Stream_IO_Error("Unix_Server_Socket: bind failed");
      }

   if(listen(fd, 100) != 0) // FIXME: totally arbitrary
      {
      ::close(fd);
      throw Stream_IO_Error("Unix_Server_Socket: listen failed");
      }

   sockfd = fd;
   }

/**
* Close a Unix socket
*/
void Unix_Server_Socket::close()
   {
   if(sockfd != -1)
      {
      if(::close(sockfd) != 0)
         throw Stream_IO_Error("Unix_Server_Socket::close failed");
      sockfd = -1;
      }
   }

/**
* Accept a new connection
*/
Socket* Unix_Server_Socket::accept()
   {
   // FIXME: grab IP of remote side, use gethostbyaddr, store as peer_id
   int retval = ::accept(sockfd, 0, 0);
   if(retval == -1)
      throw Stream_IO_Error("Unix_Server_Socket: accept failed");
   return new Unix_Socket(retval);
   }

}
