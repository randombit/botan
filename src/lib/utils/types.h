/*
* Low Level Types
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_TYPES_H__
#define BOTAN_TYPES_H__

#include <botan/build.h>
#include <botan/assert.h>
#include <cstddef>
#include <cstdint>

/**
* The primary namespace for the botan library
*/
namespace Botan {

using std::uint8_t;
using std::uint16_t;
using std::uint32_t;
using std::uint64_t;
using std::size_t;

typedef uint8_t byte;
typedef uint16_t u16bit;
typedef uint32_t u32bit;
typedef uint64_t u64bit;

typedef std::int32_t s32bit;

/**
* A default buffer size; typically a memory page
*/
static const size_t DEFAULT_BUFFERSIZE = BOTAN_DEFAULT_BUFFER_SIZE;

/**
* The two possible directions for cipher filters, determining whether they
* actually perform encryption or decryption.
*/
enum Cipher_Dir { ENCRYPTION, DECRYPTION };

}

namespace Botan_types {

using Botan::byte;
using Botan::u32bit;

}

#endif
