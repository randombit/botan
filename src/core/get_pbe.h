/*************************************************
* PBE Lookup Header File                         *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_LOOKUP_PBE_H__
#define BOTAN_LOOKUP_PBE_H__

#include <botan/pbe.h>
#include <string>

namespace Botan {

/*************************************************
* Get a PBE object                               *
*************************************************/
BOTAN_DLL PBE* get_pbe(const std::string&);
BOTAN_DLL PBE* get_pbe(const OID&, DataSource&);

}

#endif
