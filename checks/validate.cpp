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

#include "tests.h"

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

bool failed_test(const std::string&, std::vector<std::string>, bool, bool,
                 std::string&,
                 Botan::RandomNumberGenerator& rng);

std::vector<std::string> parse(const std::string&);
void strip(std::string&);

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
         const std::string ext_mark = " <EXTENSION>";
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
            std::cout << "Testing (expecting failure) "
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

   if(should_pass)
      std::cout << std::endl;

   if(should_pass)
      {
      std::vector<test_fn> all_tests;
      all_tests.push_back(test_aead);
      all_tests.push_back(test_ocb);
      all_tests.push_back(test_eax);

      all_tests.push_back(test_pbkdf);
      all_tests.push_back(test_kdf);
      all_tests.push_back(test_hkdf);
      all_tests.push_back(test_keywrap);
      all_tests.push_back(test_transform);

      all_tests.push_back(test_passhash9);
      all_tests.push_back(test_bcrypt);
      all_tests.push_back(test_cryptobox);

      run_tests(all_tests);
      }

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

   if(params.size() > 4)
      vars["ad"] = params[4];

   Algorithm_Factory& af = global_state().algorithm_factory();

   const auto results = algorithm_kat_detailed(algo, vars, af);

   bool failure = false;
   if(results.size())
      {
      for(auto i : results)
         {
         if(i.second != "passed")
            {
            std::cout << algo << " test with provider "
                      << i.first << " failed - " << i.second << "\n";
            failure = true;
            }
         }
      }

   return failure;

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

      if(!test && is_extension) return !exp_pass;

      if(!test)
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

      std::vector<byte> data = Botan::hex_decode(in);
      const byte* data_ptr = &data[0];

      // this can help catch errors with buffering, etc
      size_t len = data.size();
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
      size_t offset = random_word(rng, pipe.remaining() - 1);
      size_t length = random_word(rng, pipe.remaining() - offset);

      std::vector<byte> peekbuf(length);
      pipe.peek(&peekbuf[0], peekbuf.size(), offset);

      output = pipe.read_all_as_string();

      bool OK = true;

      for(size_t j = offset; j != offset+length; j++)
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
