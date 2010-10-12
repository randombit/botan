/*
* Unix EntropySource
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ENTROPY_SRC_UNIX_H__
#define BOTAN_ENTROPY_SRC_UNIX_H__

#include <botan/entropy_src.h>
#include <botan/internal/unix_cmd.h>
#include <vector>

namespace Botan {

/**
* Unix Entropy Source
*/
class Unix_EntropySource : public EntropySource
   {
   public:
      std::string name() const { return "Unix Entropy Source"; }

      void poll(Entropy_Accumulator& accum);

      void add_sources(const Unix_Program[], size_t);
      Unix_EntropySource(const std::vector<std::string>& path);
   private:
      static std::vector<Unix_Program> get_default_sources();
      void fast_poll(Entropy_Accumulator& accum);

      const std::vector<std::string> PATH;
      std::vector<Unix_Program> sources;
   };

}

#endif
