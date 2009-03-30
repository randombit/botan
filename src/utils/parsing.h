/*
* Parser Functions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PARSER_H__
#define BOTAN_PARSER_H__

#include <botan/types.h>
#include <string>
#include <vector>

namespace Botan {

/*
* String Parsing Functions
*/
BOTAN_DLL std::vector<std::string> parse_algorithm_name(const std::string&);
BOTAN_DLL std::vector<std::string> split_on(const std::string&, char);
BOTAN_DLL std::vector<u32bit> parse_asn1_oid(const std::string&);
BOTAN_DLL bool x500_name_cmp(const std::string&, const std::string&);

/*
* String/Integer Conversions
*/
BOTAN_DLL std::string to_string(u64bit, u32bit = 0);
BOTAN_DLL u32bit to_u32bit(const std::string&);

BOTAN_DLL u32bit timespec_to_u32bit(const std::string& timespec);

/*
* String/Network Address Conversions
*/
BOTAN_DLL u32bit string_to_ipv4(const std::string&);
BOTAN_DLL std::string ipv4_to_string(u32bit);

}

#endif
