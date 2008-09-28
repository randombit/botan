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
class FTW_EntropySource : public Buffered_EntropySource
   {
   public:
      FTW_EntropySource(const std::string& root_dir);
   private:
      void do_fast_poll();
      void do_slow_poll();

      void poll(u32bit max_read);

      const std::string path;
   };

}

#endif
