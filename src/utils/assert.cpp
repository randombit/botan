/*
* Runtime assertion checking
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/assert.h>
#include <botan/exceptn.h>
#include <sstream>

namespace Botan {

void assertion_failure(const char* expr_str,
                       const char* msg,
                       const char* func,
                       const char* file,
                       int line)
   {
   std::ostringstream format;

   format << "Assertion " << expr_str << " failed ";

   if(msg)
      format << "(" << msg << ") ";

   if(func)
      format << "in " << func << " ";

   format << "@" << file << ":" << line;

   throw Internal_Error(format.str());
   }

}
