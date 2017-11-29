/*
* (C) 2017 Fabian Weissberg, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#ifndef BOTAN_X509_DN_UB_H_
#define BOTAN_X509_DN_UB_H_

#include <botan/asn1_oid.h>

namespace Botan {

/**
* Lookup upper bounds in characters for the length of distinguished name fields
* as given in RFC 5280, Appendix A.
*
* @param oid the oid of the DN to lookup
* @return the upper bound, or SIZE_MAX if no ub is known to Botan
*/
size_t lookup_ub(const OID& oid);

}

#endif
