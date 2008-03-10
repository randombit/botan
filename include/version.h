/*************************************************
* Version Information Header File                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_VERSION_H__
#define BOTAN_VERSION_H__

#include <botan/types.h>
#include <string>

namespace Botan {

/*************************************************
* Get information describing the version         *
*************************************************/
std::string version_string();
u32bit version_major();
u32bit version_minor();
u32bit version_patch();

/*************************************************
* Macros for compile-time version checks         *
*************************************************/
#define BOTAN_VERSION_CODE_FOR(a,b,c) ((a << 16) | (b << 8) | (c))

#define BOTAN_VERSION_CODE BOTAN_VERSION_CODE_FOR(BOTAN_VERSION_MAJOR, \
                                                  BOTAN_VERSION_MINOR, \
                                                  BOTAN_VERSION_PATCH)

}

#endif
