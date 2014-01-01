/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include "tests.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <boost/regex.hpp>

#include <botan/eax.h>
#include <botan/hex.h>
#include <botan/lookup.h>

using namespace Botan;

namespace {

unsigned from_string(const std::string& s)
   {
   std::istringstream stream(s);
   unsigned n;
   stream >> n;
   return n;
   }

std::string seq(unsigned n)
   {
   std::string s;

   for(unsigned i = 0; i != n; ++i)
      {
      unsigned char b = (i & 0xFF);

      const char bin2hex[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                               '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

      s += bin2hex[(b >> 4)];
      s += bin2hex[(b & 0x0f)];
      }

   return s;
   }

size_t eax_test(const std::string& algo,
                const std::string& key_str,
                const std::string& nonce_str,
                const std::string& header_str,
                const std::string& tag_str,
                const std::string& plaintext_str,
                const std::string& ciphertext)
   {
   size_t fail = 0;

   try
      {
      EAX_Encryption enc(get_block_cipher(algo));
      EAX_Decryption dec(get_block_cipher(algo));

      enc.set_key(hex_decode(key_str));
      dec.set_key(hex_decode(key_str));

      enc.set_associated_data_vec(hex_decode(header_str));
      dec.set_associated_data_vec(hex_decode(header_str));

      secure_vector<byte> text = hex_decode_locked(plaintext_str);
      enc.start_vec(hex_decode(nonce_str));
      enc.finish(text);

      const std::string produced = hex_encode(text);

      if(produced != ciphertext + tag_str)
         {
         std::cout << "EAX " << algo << " " << produced << " != expected " << ciphertext << tag_str << "\n";
         ++fail;
         }

      text.clear();
      text = hex_decode_locked(ciphertext);
      text += hex_decode_locked(tag_str);

      dec.start_vec(hex_decode(nonce_str));
      dec.finish(text);

      const std::string decrypted = hex_encode(text);

      if(decrypted != plaintext_str)
         {
         std::cout << "EAX " << algo << " " << decrypted << " != expected " << plaintext_str << "\n";
         ++fail;
         }
      }
   catch(std::exception& e)
      {
      std::cout << "Exception during EAX test " << e.what() << "\n";
      ++fail;
      }

   return fail;
   }

std::pair<std::string, int> translate_algo(const std::string& in)
   {
   if(in == "aes (16 byte key)")
      return std::make_pair("AES-128", 16);

   if(in == "blowfish (8 byte key)")
      return std::make_pair("Blowfish", 8);

   if(in == "rc2 (8 byte key)")
      return std::make_pair("RC2", 8);

   if(in == "rc5 (8 byte key)")
      return std::make_pair("RC5", 8);

   if(in == "rc6 (16 byte key)")
      return std::make_pair("RC6", 16);

   if(in == "safer-sk128 (16 byte key)")
      return std::make_pair("SAFER-SK(10)", 16);

   if(in == "twofish (16 byte key)")
      return std::make_pair("Twofish", 16);

   if(in == "des (8 byte key)")
      return std::make_pair("DES", 8);

   if(in == "3des (24 byte key)")
      return std::make_pair("TripleDES", 24);

   // These 3 are disabled due to differences in base algorithm.

#if 0
   // XTEA: LTC uses little endian, Botan (and Crypto++) use big-endian
   // I swapped to LE in XTEA and the vectors did match
   if(in == "xtea (16 byte key)")
      return std::make_pair("XTEA", 16);

   // Skipjack: LTC uses big-endian, Botan (and Crypto++) use
   // little-endian I am not sure if that was the full difference
   // though, was unable to replicate LTC's EAX vectors with Skipjack
   if(in == "skipjack (10 byte key)")
      return std::make_pair("Skipjack", 10);

   // Noekeon: uses direct keying instead of indirect
   if(in == "noekeon (16 byte key)")
      return std::make_pair("Noekeon", 16);

#endif

   return std::make_pair("", 0);
   }

std::string rep(const std::string& s_in, unsigned n)
   {
   std::string s_out;

   for(unsigned i = 0; i != n; ++i)
      s_out += s_in[i % s_in.size()];

   return s_out;
   }

size_t eax_tests(std::istream& in)
   {
   std::string algo;
   std::string key;

   size_t fails = 0;
   size_t tests = 0;

   while(in.good())
      {
      std::string line;

      std::getline(in, line);

      if(line == "")
         continue;

      if(line.size() > 5 && line.substr(0, 4) == "EAX-")
         {
         std::pair<std::string, int> name_and_keylen =
            translate_algo(line.substr(4));

         algo = name_and_keylen.first;
         key = seq(name_and_keylen.second);
         }
      else if(algo != "")
         {
         boost::regex vec_regex("^([ 0-9]{3}): (.*), (.*)$");

         boost::smatch what;

         if(boost::regex_match(line, what, vec_regex, boost::match_extra))
            {
            unsigned n = from_string(what[1]);
            std::string ciphertext = what[2];
            std::string tag = what[3];

            std::string plaintext = seq(n);
            std::string header = seq(n);
            std::string nonce = seq(n);

            tests += 1;

            fails += eax_test(algo, key, nonce, header, tag,
                              plaintext, ciphertext);

            key = rep(tag, key.size()); // repeat as needed
            }
         }
      }

   test_report("EAX", tests, fails);

   return fails;
   }

}

size_t test_eax()
   {
   // Uses a set of tests created for libtomcrypt
   std::ifstream in(CHECKS_DIR "/eax.vec");
   return eax_tests(in);
   }
