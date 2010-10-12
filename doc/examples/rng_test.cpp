/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/botan.h>
#include <botan/x931_rng.h>
#include <botan/hex.h>
#include <botan/lookup.h>

#include <iostream>
#include <fstream>
#include <deque>
#include <stdexcept>

using namespace Botan;

namespace {

class Fixed_Output_RNG : public RandomNumberGenerator
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

      void randomize(byte out[], size_t len) throw()
         {
         for(size_t j = 0; j != len; j++)
            out[j] = random();
         }

      std::string name() const { return "Fixed_Output_RNG"; }

      void reseed(size_t) {}

      void clear() throw() {}

      void add_entropy(const byte in[], size_t len)
         {
         buf.insert(buf.end(), in, in + len);
         }

      void add_entropy_source(EntropySource* es) { delete es; }

      Fixed_Output_RNG() {}
   private:
      std::deque<byte> buf;
   };

void x931_tests(std::vector<std::pair<std::string, std::string> > vecs,
                const std::string& cipher)
   {
   for(size_t j = 0; j != vecs.size(); ++j)
      {
      const std::string result = vecs[j].first;
      const std::string input = vecs[j].second;

      ANSI_X931_RNG prng(get_block_cipher(cipher),
                         new Fixed_Output_RNG);

      SecureVector<byte> x = hex_decode(input);
      prng.add_entropy(x.begin(), x.size());

      SecureVector<byte> output(result.size() / 2);
      prng.randomize(output, output.size());

      if(hex_decode(result) != output)
         std::cout << "FAIL";
      else
         std::cout << "PASS";

      std::cout << " Seed " << input << " "
                   << "Got " << hex_encode(output) << " "
                   << "Exp " << result << "\n";
      }

   }

std::vector<std::pair<std::string, std::string> >
read_file(const std::string& fsname)
   {
   std::ifstream in(fsname.c_str());

   std::vector<std::pair<std::string, std::string> > out;

   while(in.good())
      {
      std::string line;
      std::getline(in, line);

      if(line == "")
         break;

      std::vector<std::string> l = split_on(line, ':');

      if(l.size() != 2)
         throw std::runtime_error("Bad line " + line);

      out.push_back(std::make_pair(l[0], l[1]));
      }

   return out;
   }

}

int main()
   {
   Botan::LibraryInitializer init;

   x931_tests(read_file("ANSI931_AES128VST.txt.vst"), "AES-128");
   x931_tests(read_file("ANSI931_AES192VST.txt.vst"), "AES-192");
   x931_tests(read_file("ANSI931_AES256VST.txt.vst"), "AES-256");
   x931_tests(read_file("ANSI931_TDES2VST.txt.vst"), "TripleDES");
   x931_tests(read_file("ANSI931_TDES3VST.txt.vst"), "TripleDES");
   }
