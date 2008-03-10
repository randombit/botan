/*************************************************
* OpenPGP Header File                            *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_OPENPGP_H__
#define BOTAN_OPENPGP_H__

#include <botan/data_src.h>
#include <string>
#include <map>

namespace Botan {

namespace OpenPGP {

/*************************************************
* OpenPGP Base64 encoding/decoding               *
*************************************************/
std::string encode(const byte[], u32bit, const std::string&,
                   const std::map<std::string, std::string>&);
SecureVector<byte> decode(DataSource&, std::string&,
                          std::map<std::string, std::string>&);

std::string encode(const byte[], u32bit, const std::string&);
SecureVector<byte> decode(DataSource&, std::string&);

}

}

#endif
