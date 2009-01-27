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

using Botan::byte;
using Botan::u32bit;

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

Botan::Filter* lookup(const std::string& algname,
                      const std::vector<std::string>& params,
                      const std::string& section);

Botan::Filter* lookup_block(const std::string&, const std::string&);
Botan::Filter* lookup_cipher(const std::string&, const std::string&,
                             const std::string&, bool);
Botan::Filter* lookup_hash(const std::string&);
Botan::Filter* lookup_mac(const std::string&, const std::string&);
Botan::Filter* lookup_rng(const std::string&, const std::string&);
Botan::Filter* lookup_encoder(const std::string&);
Botan::Filter* lookup_s2k(const std::string&, const std::vector<std::string>&);
Botan::Filter* lookup_kdf(const std::string&, const std::string&,
                          const std::string&);

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

      void reseed(u32bit) {}

      void randomize(byte out[], u32bit len)
         {
         for(u32bit j = 0; j != len; j++)
            out[j] = random();
         }

      std::string name() const { return "Fixed_Output_RNG"; }

      void add_entropy_source(Botan::EntropySource* src) { delete src; }
      void add_entropy(const byte[], u32bit) {};

      void clear() throw() {}

      Fixed_Output_RNG(const Botan::SecureVector<byte>& in)
         {
         buf.insert(buf.end(), in.begin(), in.begin() + in.size());
         }
      Fixed_Output_RNG(const std::string& in_str)
         {
         Botan::SecureVector<byte> in = decode_hex(in_str);
         buf.insert(buf.end(), in.begin(), in.begin() + in.size());
         }

      Fixed_Output_RNG() {}
   private:
      std::deque<byte> buf;
   };

#endif
