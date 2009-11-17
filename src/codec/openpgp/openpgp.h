/*
* OpenPGP Codec
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_OPENPGP_CODEC_H__
#define BOTAN_OPENPGP_CODEC_H__

#include <botan/data_src.h>
#include <string>
#include <map>

namespace Botan {

namespace OpenPGP {

/*
* OpenPGP Base64 encoding/decoding
*/
BOTAN_DLL std::string encode(const byte[], u32bit, const std::string&,
                                  const std::map<std::string, std::string>&);
BOTAN_DLL SecureVector<byte> decode(DataSource&, std::string&,
                                         std::map<std::string, std::string>&);

BOTAN_DLL std::string encode(const byte[], u32bit, const std::string&);
BOTAN_DLL SecureVector<byte> decode(DataSource&, std::string&);

}

}

#endif
