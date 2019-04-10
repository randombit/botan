/*
* Certificate Store
* (C) 1999-2019 Jack Lloyd
* (C) 2019      Patrick Schmidt
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/build.h>

#include <botan/certstor_linux.h>

namespace Botan {
Certificate_Store_Linux::Certificate_Store_Linux() :
   Flatfile_Certificate_Store(BOTAN_LINUX_CERTSTORE_DEFAULT_FILE)
   {
   }
}
