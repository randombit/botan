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
class BOTAN_DLL FTW_EntropySource : public EntropySource
   {
   public:
      std::string name() const { return "Proc Walker"; }

      void poll(Entropy_Accumulator& accum);

      FTW_EntropySource(const std::string& root_dir);
      ~FTW_EntropySource();

      class File_Descriptor_Source
         {
         public:
            virtual int next_fd() = 0;
            virtual ~File_Descriptor_Source() {}
         };
   private:

      std::string path;
      File_Descriptor_Source* dir;
   };

}

#endif
