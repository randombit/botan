/*************************************************
* OID Registry Header File                       *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_OIDS_H__
#define BOTAN_OIDS_H__

#include <botan/asn1_oid.h>

namespace Botan {

namespace OIDS {

/*************************************************
* Register an OID to string mapping              *
*************************************************/
void add_oid(const OID&, const std::string&);

/*************************************************
* See if an OID exists in the internal table     *
*************************************************/
bool have_oid(const std::string&);

/*************************************************
* Perform OID<->string mappings                  *
*************************************************/
std::string lookup(const OID&);
OID lookup(const std::string&);
bool name_of(const OID&, const std::string&);

}

}

#endif
