/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

/*
  Validation routines
*/

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>

#include <botan/filters.h>
#include <botan/exceptn.h>
#include <botan/selftest.h>
#include <botan/libstate.h>

#if defined(BOTAN_HAS_PASSHASH)
  #include <botan/passhash.h>
#endif

using namespace Botan;

#include "validate.h"
#include "common.h"

#define EXTRA_TESTS 0
#define DEBUG 0

namespace {

u32bit random_word(Botan::RandomNumberGenerator& rng,
                   u32bit max)
   {
#if DEBUG
   /* deterministic version for tracking down buffering bugs */
   static bool first = true;
   if(first) { srand(5); first = false; }

   u32bit r = 0;
   for(u32bit j = 0; j != 4; j++)
      r = (r << 8) | std::rand();
   return ((r % max) + 1); // return between 1 and max inclusive
#else
   /* normal version */
   u32bit r = 0;
   for(u32bit j = 0; j != 4; j++)
      r = (r << 8) | rng.next_byte();
   return ((r % max) + 1); // return between 1 and max inclusive
#endif
   }

}

Botan::Filter* lookup(const std::string&, const std::vector<std::string>&);

bool failed_test(const std::string&, std::vector<std::string>, bool, bool,
                 std::string&,
                 Botan::RandomNumberGenerator& rng);

std::vector<std::string> parse(const std::string&);
void strip(std::string&);
Botan::SecureVector<byte> decode_hex(const std::string&);

bool test_passhash(RandomNumberGenerator& rng)
   {
#if defined(BOTAN_HAS_PASSHASH)

   const std::string input = "secret";
   const std::string fixed_hash = "$9$AArBRAG0kcKp3XPDUgd32ONhutn9HMQKix7H";

   if(!password_hash_ok(input, fixed_hash))
      return false;

   std::string gen_hash = password_hash(input, rng, 5);

   if(!password_hash_ok(input, gen_hash))
      return false;

#endif

   return true;
   }

u32bit do_validation_tests(const std::string& filename,
                           RandomNumberGenerator& rng,
                           bool should_pass)
   {
   std::ifstream test_data(filename.c_str());
   bool first_mark = true;

   if(!test_data)
      throw Botan::Stream_IO_Error("Couldn't open test file " + filename);

   u32bit errors = 0, alg_count = 0;
   std::string algorithm;
   std::string section;
   std::string last_missing;
   bool is_extension = false;
   u32bit counter = 0;

   while(!test_data.eof())
      {
      if(test_data.bad() || test_data.fail())
         throw Botan::Stream_IO_Error("File I/O error reading from " +
                                      filename);

      std::string line;
      std::getline(test_data, line);

      const std::string MARK = "# MARKER: ";

      if(line.find(MARK) != std::string::npos)
         {
         if(first_mark)
            first_mark = false;
         else if(should_pass)
            std::cout << std::endl;
         counter = 0;
         section = line;
         section.replace(section.find(MARK), MARK.size(), "");
         if(should_pass)
            std::cout << "Testing " << section << ": ";
         }

      strip(line);
      if(line.size() == 0) continue;

      // Do line continuation
      while(line[line.size()-1] == '\\' && !test_data.eof())
         {
         line.replace(line.size()-1, 1, "");
         std::string nextline;
         std::getline(test_data, nextline);
         strip(nextline);
         if(nextline.size() == 0) continue;
         line += nextline;
         }

      if(line[0] == '[' && line[line.size() - 1] == ']')
         {
         const std::string ext_mark = "<EXTENSION>";
         algorithm = line.substr(1, line.size() - 2);
         is_extension = false;
         if(algorithm.find(ext_mark) != std::string::npos)
            {
            is_extension = true;
            algorithm.replace(algorithm.find(ext_mark),
                              ext_mark.length(), "");
            }

#if DEBUG
         if(should_pass)
            std::cout << "Testing " << algorithm << "..." << std::endl;
         else
            std::cout << "Testing (expecing failure) "
                      << algorithm << "..." << std::endl;
#endif
         alg_count = 0;
         continue;
         }

      std::vector<std::string> substr = parse(line);

      alg_count++;

      if(should_pass &&
         (counter % 100 == 0 || (counter < 100 && counter % 10 == 0)))
         {
         std::cout << '.';
         std::cout.flush();
         }
      counter++;

      bool failed = true; // until proven otherwise

      try
         {
         failed = failed_test(algorithm, substr,
                              is_extension, should_pass,
                              last_missing, rng);
         }
      catch(std::exception& e)
         {
         std::cout << "Exception: " << e.what() << "\n";
         }

      if(failed && should_pass)
         {
         std::cout << "ERROR: \"" << algorithm << "\" failed test #"
                   << alg_count << std::endl;
         errors++;
         }

      if(!failed && !should_pass)
         {
         std::cout << "ERROR: \"" << algorithm << "\" passed test #"
                   << alg_count << " (unexpected pass)" << std::endl;
         errors++;
         }

      }

   if(should_pass && !test_passhash(rng))
      {
      std::cout << "Passhash tests failed" << std::endl;
      errors++;
      }

   if(should_pass)
      std::cout << std::endl;
   return errors;
   }

bool failed_test(const std::string& algo,
                 std::vector<std::string> params,
                 bool is_extension, bool exp_pass,
                 std::string& last_missing,
                 Botan::RandomNumberGenerator& rng)
   {
#if !EXTRA_TESTS
   if(!exp_pass) return true;
#endif

   std::map<std::string, std::string> vars;
   vars["input"] = params[0];
   vars["output"] = params[1];

   if(params.size() > 2)
      vars["key"] = params[2];

   if(params.size() > 3)
      vars["iv"] = params[3];

   std::map<std::string, bool> results =
      algorithm_kat(algo, vars, global_state().algorithm_factory());

   if(results.size())
      {
      for(std::map<std::string, bool>::const_iterator i = results.begin();
          i != results.end(); ++i)
         {
         if(i->second == false)
            {
            std::cout << algo << " test with provider "
                      << i->first << " failed\n";
            return true;
            }
         }

      return false; // OK
      }

   const std::string in = params[0];
   const std::string expected = params[1];

   params.erase(params.begin());
   params.erase(params.begin());

   if(in.size() % 2 == 1)
      {
      std::cout << "Can't have an odd sized hex string!" << std::endl;
      return true;
      }

   Botan::Pipe pipe;

   try {
      Botan::Filter* test = lookup(algo, params);
      if(test == 0 && is_extension) return !exp_pass;
      if(test == 0)
         {
         if(algo != last_missing)
            {
            std::cout << "WARNING: \"" + algo + "\" is not a known "
                      << "algorithm name." << std::endl;
            last_missing = algo;
            }
         return 0;
         }

      pipe.reset();
      pipe.append(test);
      pipe.append(new Botan::Hex_Encoder);

      Botan::SecureVector<byte> data = decode_hex(in);
      const byte* data_ptr = data;

      // this can help catch errors with buffering, etc
      u32bit len = data.size();
      pipe.start_msg();
      while(len)
         {
         u32bit how_much = random_word(rng, len);
         pipe.write(data_ptr, how_much);
         data_ptr += how_much;
         len -= how_much;
         }
      pipe.end_msg();
      }
   catch(Botan::Algorithm_Not_Found& e)
      {
      std::cout << "Algorithm not found: " << e.what() << std::endl;
      return false;
      }
   catch(Botan::Exception& e)
      {
      if(exp_pass || DEBUG)
         std::cout << "Exception caught: " << e.what() << std::endl;
      return true;
      }
   catch(std::exception& e)
      {
      if(exp_pass || DEBUG)
         std::cout << "Standard library exception caught: "
                   << e.what() << std::endl;
      return true;
      }
   catch(...)
      {
      if(exp_pass || DEBUG)
         std::cout << "Unknown exception caught." << std::endl;
      return true;
      }

   std::string output;

   if(pipe.remaining())
      {
      /* Test peeking at an offset in Pipe/SecureQueue */
      u32bit offset = random_word(rng, pipe.remaining() - 1);
      u32bit length = random_word(rng, pipe.remaining() - offset);

      Botan::SecureVector<byte> peekbuf(length);
      pipe.peek(peekbuf, length, offset);

      output = pipe.read_all_as_string();

      bool OK = true;

      for(u32bit j = offset; j != offset+length; j++)
         if(static_cast<byte>(output[j]) != peekbuf[j-offset])
            OK = false;

      if(!OK)
         throw Botan::Self_Test_Failure("Peek testing failed in validate.cpp");
      }

   if(output == expected && !exp_pass)
      {
      std::cout << "FAILED: " << expected << " == " << std::endl
                << "        " << output << std::endl;
      return false;
      }

   if(output != expected && exp_pass)
      {
      std::cout << "\nFAILED: " << expected << " != " << std::endl
                << "        " << output << std::endl;
      return true;
      }

   if(output != expected && !exp_pass) return true;

   return false;
   }
