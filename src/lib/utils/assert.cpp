/*
* Runtime assertion checking
* (C) 2010,2012,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/exceptn.h>
#include <botan/build.h>
#include <sstream>

#if defined(BOTAN_TERMINATE_ON_ASSERTS)
  #include <cstdlib>
  #include <iostream>
#endif

namespace Botan {

void throw_invalid_argument(const char* message,
                            const BOTAN_SOURCE_LOCATION &location)
   {
   std::ostringstream format;
   format << message << " in " << location.function_name() << ":" << location.file_name();
   throw Invalid_Argument(format.str());
   }

void throw_invalid_state(const char* expr,
                         const BOTAN_SOURCE_LOCATION &location)
   {
   std::ostringstream format;
   format << "Invalid state: " << expr << " was false in " << location.function_name() << ":" << location.file_name();
   throw Invalid_State(format.str());
   }

void assertion_failure(const char* expr_str,
                       const char* assertion_made,
                       const BOTAN_SOURCE_LOCATION &location)
   {
   std::ostringstream format;

   format << "False assertion ";

   if(assertion_made && assertion_made[0] != 0)
      format << "'" << assertion_made << "' (expression " << expr_str << ") ";
   else
      format << expr_str << " ";

   format << "in " << location.function_name() << " ";

   format << "@" << location.file_name() << ":" << location.line();
   if (location.column() > 0)
   {
   format << " (" << location.column() << ")";
   }

#if defined(BOTAN_TERMINATE_ON_ASSERTS)
   std::cerr << format.str() << '\n';
   std::abort();
#else
   throw Internal_Error(format.str());
#endif
   }

}
