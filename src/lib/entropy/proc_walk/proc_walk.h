/*
* File Tree Walking EntropySource
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ENTROPY_SRC_PROC_WALK_H__
#define BOTAN_ENTROPY_SRC_PROC_WALK_H__

#include <botan/entropy_src.h>

namespace Botan {

class File_Descriptor_Source
   {
   public:
      virtual int next_fd() = 0;
      virtual ~File_Descriptor_Source() {}
   };

/**
* File Tree Walking Entropy Source
*/
class ProcWalking_EntropySource : public EntropySource
   {
   public:
      std::string name() const { return "Proc Walker"; }

      void poll(Entropy_Accumulator& accum);

      ProcWalking_EntropySource(const std::string& root_dir) :
         m_path(root_dir), m_dir(nullptr) {}

   private:
      const std::string m_path;
      std::unique_ptr<File_Descriptor_Source> m_dir;
   };

}

#endif
