/*
* File Tree Walking EntropySource
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ENTROPY_SRC_PROC_WALK_H__
#define BOTAN_ENTROPY_SRC_PROC_WALK_H__

#include <botan/entropy_src.h>
#include <memory>

namespace Botan {

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

      ~ProcWalking_EntropySource();
   private:
      const std::string m_path;
      class File_Descriptor_Source* m_dir;
   };

}

#endif
