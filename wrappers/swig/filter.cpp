/*************************************************
* SWIG Interface for Filter Retrieval            *
* (C) 1999-2003 Jack Lloyd                       *
*************************************************/

#include "base.h"
#include <botan/lookup.h>
#include <botan/filters.h>

/*************************************************
* Filter Creation                                *
*************************************************/
Filter::Filter(const char* filt_string)
   {
   filter = 0;
   pipe_owns = false;

   /*
     Fixme: This is all so totally wrong. It needs to have full argument
     processing for everything, all that kind of crap.
   */
   const std::string filt_name = filt_string;

   if(Botan::have_hash(filt_name))
      filter = new Botan::Hash_Filter(filt_name);
   else if(filt_name == "Hex_Encoder")
      filter = new Botan::Hex_Encoder;
   }

/*************************************************
* Filter Destruction                             *
*************************************************/
Filter::~Filter()
   {
   /*
   if(!pipe_owns)
      delete filter;
   */
   }
