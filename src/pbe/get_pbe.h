/*
* PBE Lookup
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_LOOKUP_PBE_H__
#define BOTAN_LOOKUP_PBE_H__

#include <botan/pbe.h>
#include <string>

namespace Botan {

/**
* Factory function for PBEs.
* @param algo_spec the name of the PBE algorithm to retrieve
* @return a pointer to a PBE with randomly created parameters
*/
BOTAN_DLL PBE* get_pbe(const std::string&);

/**
* Factory function for PBEs.
* @param pbe_oid the oid of the desired PBE
* @param params a DataSource providing the DER encoded parameters to use
* @return a pointer to the PBE with the specified parameters
*/
BOTAN_DLL PBE* get_pbe(const OID&, DataSource&);

}

#endif
