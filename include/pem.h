/*************************************************
* PEM Encoding/Decoding Header File              *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_PEM_H__
#define BOTAN_PEM_H__

#include <botan/data_src.h>
#include <botan/freestore.h>

namespace Botan {

namespace PEM_Code {

/*************************************************
* PEM Encoding/Decoding                          *
*************************************************/
std::string encode(const byte[], u32bit, const std::string&);
std::string encode(const MemoryRegion<byte>&, const std::string&);

SecureVector<byte> decode(SharedPtrConverter<DataSource>, std::string&);
SecureVector<byte> decode_check_label(SharedPtrConverter<DataSource>, const std::string&);
bool matches(SharedPtrConverter<DataSource>, const std::string& = "");

}

}

#endif
