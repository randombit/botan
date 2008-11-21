/*************************************************
* File Tree Walking EntropySource Header File    *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_ENTROPY_SRC_FTW_H__
#define BOTAN_ENTROPY_SRC_FTW_H__

#include <botan/entropy_src.h>

namespace Botan {

/*************************************************
* File Tree Walking Entropy Source               *
*************************************************/
class BOTAN_DLL FTW_EntropySource : public EntropySource
   {
   public:
      std::string name() const { return "Proc Walker"; }

      u32bit slow_poll(byte buf[], u32bit len);
      u32bit fast_poll(byte buf[], u32bit len);

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
