/*************************************************
* Parser Functions Header File                   *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_PARSER_H__
#define BOTAN_PARSER_H__

#include <botan/types.h>
#include <string>
#include <vector>

namespace Botan {

/*************************************************
* String Parsing Functions                       *
*************************************************/
std::vector<std::string> parse_algorithm_name(const std::string&);
std::vector<std::string> split_on(const std::string&, char);
std::vector<u32bit> parse_asn1_oid(const std::string&);
bool x500_name_cmp(const std::string&, const std::string&);
u32bit parse_expr(const std::string&);

/*************************************************
* String/Integer Conversions                     *
*************************************************/
std::string to_string(u64bit, u32bit = 0);
u32bit to_u32bit(const std::string&);

}

#endif
