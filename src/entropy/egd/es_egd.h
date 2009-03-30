/**
* EGD EntropySource
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ENTROPY_SRC_EGD_H__
#define BOTAN_ENTROPY_SRC_EGD_H__

#include <botan/entropy_src.h>
#include <string>
#include <vector>

namespace Botan {

/**
* EGD Entropy Source
*/
class BOTAN_DLL EGD_EntropySource : public EntropySource
   {
   public:
      std::string name() const { return "EGD/PRNGD"; }

      void poll(Entropy_Accumulator& accum);

      EGD_EntropySource(const std::vector<std::string>&);
      ~EGD_EntropySource();
   private:
      class EGD_Socket
         {
         public:
            EGD_Socket(const std::string& path);

            void close();
            u32bit read(byte outbuf[], u32bit length);
         private:
            static int open_socket(const std::string& path);

            std::string socket_path;
            int m_fd; // cached fd
         };

      std::vector<EGD_Socket> sockets;
   };

}

#endif
