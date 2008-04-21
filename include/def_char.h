/*************************************************
* Default Character Set Handling Header File     *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_DEFAULT_CHARSET_H__
#define BOTAN_DEFAULT_CHARSET_H__

#include <botan/charset.h>

namespace Botan {

/*************************************************
* Default Character Set Transcoder Object        *
*************************************************/
class BOTAN_DLL Default_Charset_Transcoder : public Charset_Transcoder
   {
   public:
      std::string transcode(const std::string&,
                            Character_Set, Character_Set) const;
   };

}

#endif
