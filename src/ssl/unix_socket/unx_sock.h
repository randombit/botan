/**
* Unix Socket Header File
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_UNIX_SOCKET_H__
#define BOTAN_UNIX_SOCKET_H__

#include <botan/socket.h>

namespace Botan {

/**
   FIXME: the current socket interface is totally unusable
     It has to handle (cleanly):
      - TCP, UDP, and SCTP, where UDP is only usable with DTLS and
        TCP/SCTP is only usable with TLS.
      - Alternate socket interfaces (ACE, Netxx, whatever) with
        minimal wrapping needed.
*/


/**
* Unix Socket Base Class
*/
class BOTAN_DLL Unix_Socket : public Socket
   {
   public:
      u32bit read(byte[], u32bit);
      void write(const byte[], u32bit);

      std::string peer_id() const;

      void close();
      Unix_Socket(int, const std::string& = "");
      Unix_Socket(const std::string&, u16bit);
      ~Unix_Socket() { close(); }
   private:
      std::string peer;
      int sockfd;
   };

/**
* Unix Server Socket Base Class
*/
class BOTAN_DLL Unix_Server_Socket : public Server_Socket
   {
   public:
      Socket* accept();
      void close();

      Unix_Server_Socket(u16bit);
      ~Unix_Server_Socket() { close(); }
   private:
      int sockfd;
   };

}

#endif
