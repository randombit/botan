/*
* Version Information
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_VERSION_H__
#define BOTAN_VERSION_H__

#include <botan/types.h>
#include <string>

namespace Botan {

/*
* Get information describing the version
*/

/**
* Get the version string identifying the version of Botan.
* @return the version string
*/
BOTAN_DLL std::string version_string();

/**
* Get the major version number.
* @return the major version number
*/
BOTAN_DLL u32bit version_major();

/**
* Get the minor version number.
* @return the minor version number
*/
BOTAN_DLL u32bit version_minor();

/**
* Get the patch number.
* @return the patch number
*/
BOTAN_DLL u32bit version_patch();

/*
* Macros for compile-time version checks
*/
#define BOTAN_VERSION_CODE_FOR(a,b,c) ((a << 16) | (b << 8) | (c))

/**
* Compare using BOTAN_VERSION_CODE_FOR, as in
*  # if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,8,0)
*  #    error "Botan version too old"
*  # endif
*/
#define BOTAN_VERSION_CODE BOTAN_VERSION_CODE_FOR(BOTAN_VERSION_MAJOR, \
                                                  BOTAN_VERSION_MINOR, \
                                                  BOTAN_VERSION_PATCH)

}

#endif
