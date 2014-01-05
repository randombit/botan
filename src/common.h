// common code for the validation and benchmark code

#ifndef BOTAN_CHECK_COMMON_H__
#define BOTAN_CHECK_COMMON_H__

#include <string>
#include "getopt.h"

void strip_comments(std::string& line);
void strip_newlines(std::string& line);
void strip(std::string& line);

inline std::string strip(const std::string& line)
   { std::string s = line; strip(s); return s; }

std::vector<std::string> parse(const std::string& line);

#endif
