/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EC_POINT_FORMAT_H_
#define BOTAN_EC_POINT_FORMAT_H_

#include <botan/types.h>

/*
* This header is public, but avoid including it directly. Instead
* get the contents via ec_group.h.
*/

namespace Botan {

/**
* This enum indicates the method used to encode the EC parameters
*
* @warning All support for explicit or implicit domain encodings
* will be removed in Botan4. Only named curves will be supported.
*
* TODO(Botan4) remove this enum
*/
enum class EC_Group_Encoding : uint8_t {
   Explicit = 0,
   ImplicitCA = 1,
   NamedCurve = 2,

   EC_DOMPAR_ENC_EXPLICIT = Explicit,
   EC_DOMPAR_ENC_IMPLICITCA = ImplicitCA,
   EC_DOMPAR_ENC_OID = NamedCurve
};

enum class EC_Point_Format : uint8_t {
   Uncompressed = 0,
   Compressed = 1,

   UNCOMPRESSED BOTAN_DEPRECATED("Use EC_Point_Format::Uncompressed") = Uncompressed,
   COMPRESSED BOTAN_DEPRECATED("Use EC_Point_Format::Compressed") = Compressed,

   Hybrid BOTAN_DEPRECATED("Hybrid point encoding is deprecated") = 2,
   HYBRID BOTAN_DEPRECATED("Hybrid point encoding is deprecated") = 2
};

}  // namespace Botan

#endif
