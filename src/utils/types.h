/*
* Low Level Types
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_TYPES_H__
#define BOTAN_TYPES_H__

#include <botan/build.h>
#include <stddef.h>

/**
* The primary namespace for the botan library
*/
namespace Botan {

/**
* Typedef representing an unsigned 8-bit quantity
*/
typedef unsigned char byte;

/**
* Typedef representing an unsigned 16-bit quantity
*/
typedef unsigned short u16bit;

/**
* Typedef representing an unsigned 32-bit quantity
*/
typedef unsigned int u32bit;

/**
* Typedef representing a signed 32-bit quantity
*/
typedef signed int s32bit;

/**
* Typedef representing an unsigned 64-bit quantity
*/
#if defined(_MSC_VER) || defined(__BORLANDC__)
   typedef unsigned __int64 u64bit;
#elif defined(__KCC)
   typedef unsigned __long_long u64bit;
#elif defined(__GNUG__)
   __extension__ typedef unsigned long long u64bit;
#else
   typedef unsigned long long u64bit;
#endif

/**
* A default buffer size; typically a memory page
*/
static const size_t DEFAULT_BUFFERSIZE = BOTAN_DEFAULT_BUFFER_SIZE;

}

namespace Botan_types {

using Botan::byte;
using Botan::u32bit;

}

#endif
