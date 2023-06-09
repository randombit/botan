/*
* OID Registry
* (C) 1999-2008,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/oids.h>

#include <botan/internal/oid_map.h>

namespace Botan {

void OIDS::add_oid2str(const OID& oid, std::string_view name) {
   OID_Map::global_registry().add_oid2str(oid, name);
}

void OIDS::add_str2oid(const OID& oid, std::string_view name) {
   OID_Map::global_registry().add_str2oid(oid, name);
}

}  // namespace Botan
