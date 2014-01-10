/*
* Runtime assertion checking
* (C) 2010,2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/exceptn.h>
#include <sstream>

namespace Botan {

void assertion_failure(const char* expr_str,
                       const char* assertion_made,
                       const char* func,
                       const char* file,
                       int line)
   {
   std::ostringstream format;

   format << "False assertion ";

   if(assertion_made && assertion_made[0] != 0)
      format << "'" << assertion_made << "' (expression " << expr_str << ") ";
   else
      format << expr_str << " ";

   if(func)
      format << "in " << func << " ";

   format << "@" << file << ":" << line;

   throw std::runtime_error(format.str());
   }

}
