/*
* Certificate Store
* (C) 1999-2019 Jack Lloyd
* (C) 2019      Patrick Schmidt
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CERT_STORE_SYSTEM_LINUX_H_
#define BOTAN_CERT_STORE_SYSTEM_LINUX_H_

#include <botan/certstor_flatfile.h>

namespace Botan {

/**
* Certificate Store that is backed by a file of PEMs of trusted CAs located at
* BOTAN_LINUX_CERTSTORE_DEFAULT_FILE.
*/
class BOTAN_PUBLIC_API(2, 11) Certificate_Store_Linux final : public Flatfile_Certificate_Store
   {
   public:
      Certificate_Store_Linux();
   };
}

#endif
