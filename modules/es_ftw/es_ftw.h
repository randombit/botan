/*************************************************
* File Tree Walking EntropySource Header File    *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_EXT_ENTROPY_SRC_FTW_H__
#define BOTAN_EXT_ENTROPY_SRC_FTW_H__

#include <botan/buf_es.h>

namespace Botan {

/*************************************************
* File Tree Walking Entropy Source               *
*************************************************/
class FTW_EntropySource : public Buffered_EntropySource
   {
   public:
      FTW_EntropySource(const std::string& = "/proc");
   private:
      void do_fast_poll();
      void do_slow_poll();
      void gather_from_dir(const std::string&);
      void gather_from_file(const std::string&);
      const std::string path;
      u32bit files_read, max_read;
   };

}

#endif
