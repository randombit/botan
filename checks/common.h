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

Botan::Filter* lookup(const std::string& algname,
                      const std::vector<std::string>& params);

class Fixed_Output_RNG : public Botan::RandomNumberGenerator
   {
   public:
      bool is_seeded() const { return !buf.empty(); }

      byte random()
         {
         if(buf.empty())
            throw std::runtime_error("Out of bytes");

         byte out = buf.front();
         buf.pop_front();
         return out;
         }

      void reseed(size_t) {}

      void randomize(byte out[], size_t len)
         {
         for(size_t j = 0; j != len; j++)
            out[j] = random();
         }

      std::string name() const { return "Fixed_Output_RNG"; }

      void add_entropy_source(Botan::EntropySource* src) { delete src; }
      void add_entropy(const byte[], size_t) {};

      void clear() throw() {}

      Fixed_Output_RNG(const Botan::SecureVector<byte>& in)
         {
         buf.insert(buf.end(), in.begin(), in.end());
         }
      Fixed_Output_RNG(const std::string& in_str)
         {
         Botan::SecureVector<byte> in = Botan::hex_decode(in_str);
         buf.insert(buf.end(), in.begin(), in.end());
         }

      Fixed_Output_RNG() {}
   private:
      std::deque<byte> buf;
   };

#endif
