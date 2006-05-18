/*************************************************
* OID Registry Header File                       *
* (C) 1999-2006 The Botan Project                *
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
* Do an OID to string lookup                     *
*************************************************/
std::string lookup(const OID&);

/*************************************************
* Do a string to OID lookup                      *
*************************************************/
OID lookup(const std::string&);

/*************************************************
* See if an OID exists in the internal table     *
*************************************************/
bool have_oid(const std::string&);

}

}

#endif
