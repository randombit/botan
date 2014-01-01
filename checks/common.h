// common code for the validation and benchmark code

#ifndef BOTAN_CHECK_COMMON_H__
#define BOTAN_CHECK_COMMON_H__

#include <vector>
#include <string>
#include <deque>
#include <stdexcept>

#include <botan/secmem.h>
#include <botan/filter.h>
#include <botan/rng.h>
#include <botan/hex.h>

using Botan::byte;
using Botan::u32bit;
using Botan::u64bit;

void strip_comments(std::string& line);
void strip_newlines(std::string& line);
void strip(std::string& line);
std::vector<std::string> parse(const std::string& line);

#endif
