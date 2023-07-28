/*
* (C) 2015 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_UTIL_FILESYSTEM_H_
#define BOTAN_UTIL_FILESYSTEM_H_

#include <botan/exceptn.h>
#include <string>
#include <vector>

namespace Botan {

/**
* No_Filesystem_Access Exception
*/
class No_Filesystem_Access final : public Exception {
   public:
      No_Filesystem_Access() : Exception("No filesystem access enabled.") {}
};

BOTAN_TEST_API bool has_filesystem_impl();

BOTAN_TEST_API std::vector<std::string> get_files_recursive(std::string_view dir);

}  // namespace Botan

#endif
