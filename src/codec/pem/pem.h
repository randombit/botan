/*
* PEM Encoding/Decoding
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PEM_H__
#define BOTAN_PEM_H__

#include <botan/data_src.h>

namespace Botan {

namespace PEM_Code {

/*
* PEM Encoding/Decoding
*/
BOTAN_DLL std::string encode(const byte[], size_t,
                             const std::string&, size_t = 64);
BOTAN_DLL std::string encode(const MemoryRegion<byte>&,
                             const std::string&, size_t = 64);

BOTAN_DLL SecureVector<byte> decode(DataSource&, std::string&);
BOTAN_DLL SecureVector<byte> decode_check_label(DataSource&,
                                                const std::string&);
BOTAN_DLL bool matches(DataSource&, const std::string& = "",
                       size_t search_range = 4096);

}

}

#endif
