/*
* File Tree Walking EntropySource
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ENTROPY_SRC_PROC_WALK_H_
#define BOTAN_ENTROPY_SRC_PROC_WALK_H_

#include <botan/entropy_src.h>
#include <botan/mutex.h>

namespace Botan {

class File_Descriptor_Source
   {
   public:
      virtual int next_fd() = 0;
      virtual ~File_Descriptor_Source() = default;
   };

/**
* File Tree Walking Entropy Source
*/
class ProcWalking_EntropySource final : public Entropy_Source
   {
   public:
      std::string name() const override { return "proc_walk"; }

      size_t poll(RandomNumberGenerator& rng) override;

      explicit ProcWalking_EntropySource(const std::string& root_dir) :
         m_path(root_dir), m_dir(nullptr) {}

   private:
      const std::string m_path;
      mutex_type m_mutex;
      std::unique_ptr<File_Descriptor_Source> m_dir;
      secure_vector<uint8_t> m_buf;
   };

}

#endif
