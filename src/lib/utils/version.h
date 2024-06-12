/*
* Version Information
* (C) 1999-2011,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_VERSION_H_
#define BOTAN_VERSION_H_

#include <botan/types.h>
#include <string>

namespace Botan {

/*
* Get information describing the version
*/

/**
* Get a human-readable single-line string identifying the version of Botan.
* No particular format should be assumed.
* @return version string
*/
BOTAN_PUBLIC_API(2, 0) std::string version_string();

/**
* Same as version_string() except returning a pointer to a statically
* allocated string.
* @return version string
*/
BOTAN_PUBLIC_API(2, 0) const char* version_cstr();

/**
* Return a version string of the form "MAJOR.MINOR.PATCH" where
* each of the values is an integer.
*/
BOTAN_PUBLIC_API(2, 4) std::string short_version_string();

/**
* Same as version_short_string except returning a pointer to the string.
*/
BOTAN_PUBLIC_API(2, 4) const char* short_version_cstr();

/**
* Return the date this version of botan was released, in an integer of
* the form YYYYMMDD. For instance a version released on May 21, 2013
* would return the integer 20130521. If the currently running version
* is not an official release, this function will return 0 instead.
*
* @return release date, or zero if unreleased
*/
BOTAN_PUBLIC_API(2, 0) uint32_t version_datestamp();

/**
* Get the major version number.
* @return major version number
*/
BOTAN_PUBLIC_API(2, 0) uint32_t version_major();

/**
* Get the minor version number.
* @return minor version number
*/
BOTAN_PUBLIC_API(2, 0) uint32_t version_minor();

/**
* Get the patch number.
* @return patch number
*/
BOTAN_PUBLIC_API(2, 0) uint32_t version_patch();

/**
* Usable for checking that the DLL version loaded at runtime exactly matches the
* compile-time version. Call using BOTAN_VERSION_* macro values, like so:
*
* ```
* Botan::runtime_version_check(BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH);
* ```
*
* It will return an empty string if the versions match, or otherwise an error
* message indicating the discrepancy. This only is useful in dynamic libraries,
* where it is possible to compile and run against different versions.
*/
BOTAN_PUBLIC_API(2, 0) std::string runtime_version_check(uint32_t major, uint32_t minor, uint32_t patch);

/*
* Macros for compile-time version checks
*
* Return a value that can be used to compare versions. The current
* (compile-time) version is available as the macro BOTAN_VERSION_CODE. For
* instance, to choose one code path for version 3.1.0 and later, and another
* code path for older releases:
*
* ```
* #if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(3,1,0)
*    // 3.1+ code path
* #else
*    // code path for older versions
* #endif
* ```
*/
#define BOTAN_VERSION_CODE_FOR(a, b, c) ((a << 16) | (b << 8) | (c))

/**
* Compare using BOTAN_VERSION_CODE_FOR, as in
*  # if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,8,0)
*  #    error "Botan version too old"
*  # endif
*/
#define BOTAN_VERSION_CODE BOTAN_VERSION_CODE_FOR(BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH)

}  // namespace Botan

#endif
