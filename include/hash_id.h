/*************************************************
* Hash Function Identification Header File       *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_HASHID_H__
#define BOTAN_HASHID_H__

#include <botan/secmem.h>
#include <string>

namespace Botan {

/*************************************************
* Return the values of various defined HashIDs   *
*************************************************/
MemoryVector<byte> pkcs_hash_id(const std::string&);
byte ieee1363_hash_id(const std::string&);

}

#endif
