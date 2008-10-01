/*************************************************
* OID Registry Header File                       *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_OIDS_H__
#define BOTAN_OIDS_H__

#include <botan/asn1_oid.h>

namespace Botan {

namespace OIDS {

/*************************************************
* Register an OID to string mapping              *
*************************************************/
BOTAN_DLL void add_oid(const OID&, const std::string&);

/*************************************************
* See if an OID exists in the internal table     *
*************************************************/
BOTAN_DLL bool have_oid(const std::string&);

/*************************************************
* Perform OID<->string mappings                  *
*************************************************/
BOTAN_DLL std::string lookup(const OID&);
BOTAN_DLL OID lookup(const std::string&);
BOTAN_DLL bool name_of(const OID&, const std::string&);

}

}

#endif
