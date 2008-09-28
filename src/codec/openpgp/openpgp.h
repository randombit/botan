/*************************************************
* OpenPGP Header File                            *
* (C) 1999-2007 Jack Lloyd                       *
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
BOTAN_DLL std::string encode(const byte[], u32bit, const std::string&,
                                  const std::map<std::string, std::string>&);
BOTAN_DLL SecureVector<byte> decode(DataSource&, std::string&,
                                         std::map<std::string, std::string>&);

BOTAN_DLL std::string encode(const byte[], u32bit, const std::string&);
BOTAN_DLL SecureVector<byte> decode(DataSource&, std::string&);

}

}

#endif
