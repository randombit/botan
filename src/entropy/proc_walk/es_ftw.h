/*
* File Tree Walking EntropySource
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ENTROPY_SRC_FTW_H__
#define BOTAN_ENTROPY_SRC_FTW_H__

#include <botan/entropy_src.h>

namespace Botan {

/**
* File Tree Walking Entropy Source
*/
class FTW_EntropySource : public EntropySource
   {
   public:
      std::string name() const { return "Proc Walker"; }

      void poll(Entropy_Accumulator& accum);

      FTW_EntropySource(const std::string& root_dir);
      ~FTW_EntropySource();
   private:
      std::string path;
      class File_Descriptor_Source* dir;
   };

}

#endif
