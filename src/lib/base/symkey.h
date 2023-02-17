/*
* OctetString
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SYMKEY_H_
#define BOTAN_SYMKEY_H_

#include <botan/secmem.h>
#include <botan/strong_type.h>

namespace Botan {

using OctetString = Strong<secure_vector<uint8_t>, struct OctetString_, Strong_Capability::XORable, Strong_Capability::DeprecatedOctetStringMethods>;

/**
* Alternate name for octet string showing intent to use as a key
*/
using SymmetricKey = OctetString;

/**
* Alternate name for octet string showing intent to use as an IV
*/
using InitializationVector = OctetString;

}

#endif
