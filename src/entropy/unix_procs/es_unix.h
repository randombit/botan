/*
* Unix EntropySource
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ENTROPY_SRC_UNIX_H__
#define BOTAN_ENTROPY_SRC_UNIX_H__

#include <botan/entropy_src.h>
#include <botan/unix_cmd.h>
#include <vector>

namespace Botan {

/**
* Unix Entropy Source
*/
class BOTAN_DLL Unix_EntropySource : public EntropySource
   {
   public:
      std::string name() const { return "Unix Entropy Source"; }

      void poll(Entropy_Accumulator& accum);

      void add_sources(const Unix_Program[], u32bit);
      Unix_EntropySource(const std::vector<std::string>& path);
   private:
      static void add_default_sources(std::vector<Unix_Program>&);
      void fast_poll(Entropy_Accumulator& accum);

      const std::vector<std::string> PATH;
      std::vector<Unix_Program> sources;
   };

}

#endif
