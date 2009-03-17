#include <botan/botan.h>
#include <botan/x931_rng.h>
#include <botan/filters.h>
#include <botan/lookup.h>

#include <iostream>
#include <fstream>
#include <boost/algorithm/string.hpp>
#include <stdexcept>

using namespace Botan;

std::vector<std::pair<std::string, std::string> > read_file(const std::string&);

SecureVector<byte> decode_hex(const std::string& in)
   {
   SecureVector<byte> result;

   try {
      Botan::Pipe pipe(new Botan::Hex_Decoder);
      pipe.process_msg(in);
      result = pipe.read_all();
   }
   catch(std::exception& e)
      {
      result.destroy();
      }
   return result;
   }

std::string hex_encode(const byte in[], u32bit len)
   {
   Botan::Pipe pipe(new Botan::Hex_Encoder);
   pipe.process_msg(in, len);
   return pipe.read_all_as_string();
   }

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

      void randomize(byte out[], u32bit len) throw()
         {
         for(u32bit j = 0; j != len; j++)
            out[j] = random();
         }

      std::string name() const { return "Fixed_Output_RNG"; }

      void reseed(u32bit) {}

      void clear() throw() {}

      void add_entropy(const byte in[], u32bit len)
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

      SecureVector<byte> x = decode_hex(input);
      prng.add_entropy(x.begin(), x.size());

      SecureVector<byte> output(result.size() / 2);
      prng.randomize(output, output.size());

      if(decode_hex(result) != output)
         std::cout << "FAIL";
      else
         std::cout << "PASS";

      std::cout << " Seed " << input << " "
                   << "Got " << hex_encode(output, output.size()) << " "
                   << "Exp " << result << "\n";
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

      std::vector<std::string> l;
      boost::split(l, line, boost::is_any_of(":"));

      if(l.size() != 2)
         throw std::runtime_error("Bad line " + line);

      out.push_back(std::make_pair(l[0], l[1]));
      }

   return out;
   }
