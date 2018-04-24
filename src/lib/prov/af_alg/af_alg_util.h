/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AF_ALG_UTIL_H_
#define BOTAN_AF_ALG_UTIL_H_

#include <botan/exceptn.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <unistd.h>
#include <cstring>

namespace Botan {

class AF_Alg_Socket final
   {
   public:
      AF_Alg_Socket(const std::string& type,
                    const std::string& name)
         {
         m_algo_fd = ::socket(AF_ALG, SOCK_SEQPACKET, 0);
         if(m_algo_fd < 0)
            throw Exception("Creating AF_ALG socket failed");

         struct sockaddr_alg sa;
         memset(&sa, 0, sizeof(sa));
         sa.salg_family = AF_ALG;
         if(type.size() > sizeof(sa.salg_type) ||
            name.size() > sizeof(sa.salg_name))
            throw Exception("Input type/name too large for AF_ALG socket type");

         std::strcpy(reinterpret_cast<char*>(sa.salg_type), type.c_str());
         std::strcpy(reinterpret_cast<char*>(sa.salg_name), name.c_str());

         if(::bind(m_algo_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
            throw Exception("Unknown AF_ALG algorithm"); // presumably

         m_op_fd = ::accept(m_algo_fd, nullptr, nullptr);
         if(m_op_fd < 0)
            throw Exception("Getting AF_ALG operation socket failed");
         }

      ~AF_Alg_Socket()
         {
         ::close(m_algo_fd);
         ::close(m_op_fd);
         }

      AF_Alg_Socket(const AF_Alg_Socket&) = delete;
      AF_Alg_Socket& operator=(const AF_Alg_Socket&) = delete;

      void write_data(const uint8_t buf[], size_t len, bool more) const
         {
         int flags = more ? MSG_MORE : 0;
         ssize_t wrote = ::send(m_op_fd, buf, len, flags);

         if(wrote < 0 || static_cast<size_t>(wrote) != len)
            throw Exception("AF_ALG error send truncated");
         }

      void read_data(uint8_t buf[], size_t len) const
         {
         size_t got = ::recv(m_op_fd, buf, len, 0);

         if(got != len)
            throw Exception("AF_ALG read was truncated");
         }

   private:
      int m_algo_fd;
      int m_op_fd;
   };

}

#endif
