/*************************************************
* File Tree Walking EntropySource Header File    *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_ENTROPY_SRC_FTW_H__
#define BOTAN_ENTROPY_SRC_FTW_H__

#include <botan/buf_es.h>

namespace Botan {

/*************************************************
* File Tree Walking Entropy Source               *
*************************************************/
class BOTAN_DLL FTW_EntropySource : public Buffered_EntropySource
   {
   public:
      std::string name() const { return "Proc Walker"; }

      FTW_EntropySource(const std::string& root_dir);
      ~FTW_EntropySource();

      class File_Descriptor_Source
         {
         public:
            virtual int next_fd() = 0;
            virtual ~File_Descriptor_Source() {}
         };
   private:
      void do_fast_poll();
      void do_slow_poll();

      void poll(u32bit max_read);

      const std::string path;
      File_Descriptor_Source* dir;
   };

}

#endif
