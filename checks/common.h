// common code for the validation and benchmark code
// this file is in the public domain

#ifndef BOTANCHECK_COMMON_H__
#define BOTANCHECK_COMMON_H__

#include <vector>
#include <string>

struct algorithm
   {
      algorithm(const char* t, const char* n,
                u32bit k = 0, u32bit i = 0) :
         type(t), name(n), filtername(n), keylen(k), ivlen(i) {}
      algorithm(const char* t, const char* n,
                const char* f, u32bit k = 0, u32bit i = 0) :
         type(t), name(n), filtername(f), keylen(k), ivlen(i) {}
      std::string type, name, filtername;
      u32bit keylen, ivlen, weight;
   };

std::vector<algorithm> get_algos();

void strip_comments(std::string& line);
void strip_newlines(std::string& line);
void strip(std::string& line);
std::vector<std::string> parse(const std::string& line);

std::string hex_encode(const byte in[], u32bit len);
Botan::SecureVector<byte> decode_hex(const std::string&);

Botan::u64bit get_clock();
Botan::u64bit get_ticks();

#endif
