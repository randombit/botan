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
*
* TODO(Botan4): Move EC_Point_Format to ec_group.h and delete this file
*/

namespace Botan {

enum class EC_Point_Format {
   Uncompressed = 0,
   Compressed = 1,

   UNCOMPRESSED BOTAN_DEPRECATED("Use EC_Point_Format::Uncompressed") = Uncompressed,
   COMPRESSED BOTAN_DEPRECATED("Use EC_Point_Format::Compressed") = Compressed,

   Hybrid BOTAN_DEPRECATED("Hybrid point encoding is deprecated") = 2,
   HYBRID BOTAN_DEPRECATED("Hybrid point encoding is deprecated") = 2
};

}  // namespace Botan

#endif
