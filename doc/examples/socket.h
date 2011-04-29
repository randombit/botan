/*
* Unix Socket
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef SOCKET_WRAPPER_H__
#define SOCKET_WRAPPER_H__

#include <stdexcept>

#if defined(_MSC_VER)
  #define SOCKET_IS_WINSOCK 1
#endif

#if !defined(SOCKET_IS_WINSOCK)
  #define SOCKET_IS_WINSOCK 0
#endif

#if SOCKET_IS_WINSOCK
  #include <winsock.h>

  typedef SOCKET socket_t;
  const socket_t invalid_socket = INVALID_SOCKET;
  #define socket_error_code WSAGetLastError()
  typedef int ssize_t;

  class SocketInitializer
     {
     public:
        SocketInitializer()
           {
           WSADATA wsadata;
           WSAStartup(MAKEWORD(2, 2), &wsadata);
           }

        ~SocketInitializer()
           {
           WSACleanup();
           }
     };
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <sys/time.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <errno.h>

  typedef int socket_t;
  const socket_t invalid_socket = -1;
  #define socket_error_code errno
  #define closesocket close

  class SocketInitializer {};
#endif

#if !defined(MSG_NOSIGNAL)
  #define MSG_NOSIGNAL 0
#endif

#include <string.h>

class Socket
   {
   public:
      size_t read(unsigned char[], size_t);
      void write(const unsigned char[], size_t);

      std::string peer_id() const { return peer; }

      void close()
         {
         if(sockfd != invalid_socket)
            {
            if(::closesocket(sockfd) != 0)
               throw std::runtime_error("Socket::close failed");
            sockfd = invalid_socket;
            }
         }

      Socket(socket_t fd, const std::string& peer_id = "") :
         peer(peer_id), sockfd(fd)
         {
         }

      Socket(const std::string&, unsigned short);
      ~Socket() { close(); }
   private:
      std::string peer;
      socket_t sockfd;
   };

class Server_Socket
   {
   public:
      /**
      * Accept a new connection
      */
      Socket* accept()
         {
         socket_t retval = ::accept(sockfd, 0, 0);
         if(retval == invalid_socket)
            throw std::runtime_error("Server_Socket: accept failed");
         return new Socket(retval);
         }

      void close()
         {
         if(sockfd != invalid_socket)
            {
            if(::closesocket(sockfd) != 0)
               throw std::runtime_error("Server_Socket::close failed");
            sockfd = invalid_socket;
            }
         }

      Server_Socket(unsigned short);
      ~Server_Socket() { close(); }
   private:
      socket_t sockfd;
   };

/**
* Unix Socket Constructor
*/
Socket::Socket(const std::string& host, unsigned short port) : peer(host)
   {
   sockfd = invalid_socket;

   hostent* host_addr = ::gethostbyname(host.c_str());

   if(host_addr == 0)
      throw std::runtime_error("Socket: gethostbyname failed for " + host);
   if(host_addr->h_addrtype != AF_INET) // FIXME
      throw std::runtime_error("Socket: " + host + " has IPv6 address");

   socket_t fd = ::socket(PF_INET, SOCK_STREAM, 0);
   if(fd == invalid_socket)
      throw std::runtime_error("Socket: Unable to acquire socket");

   sockaddr_in socket_info;
   ::memset(&socket_info, 0, sizeof(socket_info));
   socket_info.sin_family = AF_INET;
   socket_info.sin_port = htons(port);

   ::memcpy(&socket_info.sin_addr,
            host_addr->h_addr,
            host_addr->h_length);

   socket_info.sin_addr = *(struct in_addr*)host_addr->h_addr; // FIXME

   if(::connect(fd, (sockaddr*)&socket_info, sizeof(struct sockaddr)) != 0)
      {
      ::closesocket(fd);
      throw std::runtime_error("Socket: connect failed");
      }

   sockfd = fd;
   }

/**
* Read from a Unix socket
*/
size_t Socket::read(unsigned char buf[], size_t length)
   {
   if(sockfd == invalid_socket)
      throw std::runtime_error("Socket::read: Socket not connected");

   size_t got = 0;

   while(length)
      {
      ssize_t this_time = ::recv(sockfd, (char*)buf + got,
                                 length, MSG_NOSIGNAL);

      if(this_time == 0)
         break;

      if(this_time == -1)
         {
         if(socket_error_code == EINTR)
            this_time = 0;
         else
            throw std::runtime_error("Socket::read: Socket read failed");
         }

      got += this_time;
      length -= this_time;
      }
   return got;
   }

/**
* Write to a Unix socket
*/
void Socket::write(const unsigned char buf[], size_t length)
   {
   if(sockfd == invalid_socket)
      throw std::runtime_error("Socket::write: Socket not connected");

   size_t offset = 0;
   while(length)
      {
      ssize_t sent = ::send(sockfd, (const char*)buf + offset,
                            length, MSG_NOSIGNAL);

      if(sent == -1)
         {
         if(socket_error_code == EINTR)
            sent = 0;
         else
            throw std::runtime_error("Socket::write: Socket write failed");
         }

      offset += sent;
      length -= sent;
      }
   }

/**
* Unix Server Socket Constructor
*/
Server_Socket::Server_Socket(unsigned short port)
   {
   sockfd = invalid_socket;

   socket_t fd = ::socket(PF_INET, SOCK_STREAM, 0);
   if(fd == invalid_socket)
      throw std::runtime_error("Server_Socket: Unable to acquire socket");

   sockaddr_in socket_info;
   ::memset(&socket_info, 0, sizeof(socket_info));
   socket_info.sin_family = AF_INET;
   socket_info.sin_port = htons(port);

   // FIXME: support limiting listeners
   socket_info.sin_addr.s_addr = INADDR_ANY;

   if(::bind(fd, (sockaddr*)&socket_info, sizeof(struct sockaddr)) != 0)
      {
      ::closesocket(fd);
      throw std::runtime_error("Server_Socket: bind failed");
      }

   if(::listen(fd, 100) != 0) // FIXME: totally arbitrary
      {
      ::closesocket(fd);
      throw std::runtime_error("Server_Socket: listen failed");
      }

   sockfd = fd;
   }

#endif
