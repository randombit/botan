/*
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TESTS_FIXED_RNG_H__
#define BOTAN_TESTS_FIXED_RNG_H__

#include <deque>
#include <string>
#include <stdexcept>
#include <botan/rng.h>
#include <botan/hex.h>

using Botan::byte;

class Fixed_Output_RNG : public Botan::RandomNumberGenerator
   {
   public:
      bool is_seeded() const { return !buf.empty(); }

      byte random()
         {
         if(!is_seeded())
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

      void add_entropy(const byte b[], size_t s)
         {
         buf.insert(buf.end(), b, b + s);
         }

      std::string name() const { return "Fixed_Output_RNG"; }

      void clear() throw() {}

      Fixed_Output_RNG(const std::vector<byte>& in)
         {
         buf.insert(buf.end(), in.begin(), in.end());
         }

      Fixed_Output_RNG(const std::string& in_str)
         {
         std::vector<byte> in = Botan::hex_decode(in_str);
         buf.insert(buf.end(), in.begin(), in.end());
         }

      Fixed_Output_RNG() {}
   protected:
      size_t remaining() const { return buf.size(); }
   private:
      std::deque<byte> buf;
   };

#endif
