/*
* Runtime assertion checking
* (C) 2010,2012,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/assert.h>

#include <botan/exceptn.h>
#include <botan/range_concepts.h>
#include <botan/internal/fmt.h>
#include <botan/internal/target_info.h>
#include <sstream>

#if defined(BOTAN_TERMINATE_ON_ASSERTS)
   #include <cstdlib>
   #include <iostream>
#endif

namespace Botan {

void throw_invalid_argument(const char* message, const char* func, const char* file) {
   throw Invalid_Argument(fmt("{} in {}:{}", message, func, file));
}

void throw_invalid_state(const char* expr, const char* func, const char* file) {
   throw Invalid_State(fmt("Invalid state: expr {} was false in {}:{}", expr, func, file));
}

// Declared in concepts.h
void ranges::memory_region_size_violation() {
   throw Invalid_Argument("Memory regions did not have expected byte lengths");
}

void assertion_failure(const char* expr_str, const char* assertion_made, const char* func, const char* file, int line) {
   std::ostringstream format;

   format << "False assertion ";

   if(assertion_made != nullptr && assertion_made[0] != 0) {
      format << "'" << assertion_made << "' (expression " << expr_str << ") ";
   } else {
      format << expr_str << " ";
   }

   if(func != nullptr) {
      format << "in " << func << " ";
   }

   format << "@" << file << ":" << line;

#if defined(BOTAN_TERMINATE_ON_ASSERTS)
   std::cerr << format.str() << '\n';
   std::abort();
#else
   throw Internal_Error(format.str());
#endif
}

void assert_unreachable(const char* file, int line) {
   const std::string msg = fmt("Codepath that was marked unreachable was reached @{}:{}", file, line);

#if defined(BOTAN_TERMINATE_ON_ASSERTS)
   std::cerr << msg << '\n';
   std::abort();
#else
   throw Internal_Error(msg);
#endif
}

}  // namespace Botan
