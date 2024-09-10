/*
* Public Key Interface
* (C) 1999-2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PK_ENUMS_H_
#define BOTAN_PK_ENUMS_H_

#include <botan/types.h>

namespace Botan {

/**
* Enumeration specifying the signature format.
*
* This is mostly used for requesting DER encoding of ECDSA signatures;
* most other algorithms only support "standard".
*/
enum class Signature_Format {
   Standard,
   DerSequence,

   IEEE_1363 BOTAN_DEPRECATED("Use Standard") = Standard,
   DER_SEQUENCE BOTAN_DEPRECATED("Use DerSequence") = DerSequence,
};

/**
* Enumeration of possible operations a public key could be used for.
*
* It is possible to query if a key supports a particular operation
* type using Asymmetric_Key::supports_operation()
*/
enum class PublicKeyOperation {
   Encryption,
   Signature,
   KeyEncapsulation,
   KeyAgreement,
};

}  // namespace Botan

#endif
