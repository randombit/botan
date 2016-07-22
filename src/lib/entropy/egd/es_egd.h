/*
* EGD EntropySource
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ENTROPY_SRC_EGD_H__
#define BOTAN_ENTROPY_SRC_EGD_H__

#include <botan/entropy_src.h>
#include <string>
#include <vector>
#include <mutex>

namespace Botan {

/**
* EGD Entropy Source
*/
class EGD_EntropySource final : public Entropy_Source
   {
   public:
      std::string name() const override { return "egd"; }

      size_t poll(RandomNumberGenerator& rng) override;

      EGD_EntropySource(const std::vector<std::string>&);
      ~EGD_EntropySource();
   private:
      class EGD_Socket
         {
         public:
            EGD_Socket(const std::string& path);

            void close();
            size_t read(byte outbuf[], size_t length);
         private:
            static int open_socket(const std::string& path);

            std::string m_socket_path;
            int m_fd; // cached fd
         };

      std::mutex m_mutex;
      std::vector<EGD_Socket> m_sockets;
      secure_vector<uint8_t> m_io_buf;
   };

}

#endif
