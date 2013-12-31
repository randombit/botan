#include "tests.h"

#include <botan/libstate.h>
#include <botan/x931_rng.h>
#include <botan/aes.h>
#include <botan/des.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>
#include <deque>

using namespace Botan;

namespace {

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
   private:
      std::deque<byte> buf;
   };

RandomNumberGenerator* get_x931(const std::string& algo, const std::string& ikm_hex)
   {
   const auto ikm = hex_decode(ikm_hex);

   if(algo == "X9.31-RNG(TripleDES)")
      return new ANSI_X931_RNG(new TripleDES, new Fixed_Output_RNG(ikm));
   else if(algo == "X9.31-RNG(AES-128)")
      return new ANSI_X931_RNG(new AES_128, new Fixed_Output_RNG(ikm));
   else if(algo == "X9.31-RNG(AES-192)")
      return new ANSI_X931_RNG(new AES_192, new Fixed_Output_RNG(ikm));
   else if(algo == "X9.31-RNG(AES-256)")
      return new ANSI_X931_RNG(new AES_256, new Fixed_Output_RNG(ikm));

   return nullptr;
   }

bool x931_test(const std::string& algo,
               const std::string& ikm,
               const std::string& out,
               size_t L)
   {
   std::unique_ptr<RandomNumberGenerator> x931(get_x931(algo, ikm));
   x931->reseed(0);

   const std::string got = hex_encode(x931->random_vec(L));

   if(got != out)
      {
      std::cout << "X9.31 " << got << " != " << out << "\n";
      return false;
      }

   return true;
   }

}

size_t test_rngs()
   {
   std::ifstream vec("checks/x931.vec");

   return run_tests_bb(vec, "RNG", "Out", true,
             [](std::map<std::string, std::string> m) -> bool
             {
             return x931_test(m["RNG"], m["IKM"], m["Out"], to_u32bit(m["L"]));
             });
   }
