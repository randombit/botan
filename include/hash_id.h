/*************************************************
* Hash Function Identification Header File       *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_HASHID_H__
#define BOTAN_HASHID_H__

#include <botan/secmem.h>
#include <string>

namespace Botan {

/*************************************************
* Return the values of various defined HashIDs   *
*************************************************/
BOTAN_DLL MemoryVector<byte> pkcs_hash_id(const std::string&);
BOTAN_DLL byte ieee1363_hash_id(const std::string&);

}

#endif
