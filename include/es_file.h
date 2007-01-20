/*************************************************
* File EntropySource Header File                 *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_ENTROPY_SRC_FILE_H__
#define BOTAN_ENTROPY_SRC_FILE_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* File Based Entropy Source                      *
*************************************************/
class File_EntropySource : public EntropySource
   {
   public:
      u32bit slow_poll(byte[], u32bit);
   };

}

#endif
