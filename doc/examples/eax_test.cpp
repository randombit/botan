/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <fstream>
#include <iostream>
#include <sstream>
#include <boost/regex.hpp>

#include <botan/botan.h>
#include <botan/eax.h>

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

void eax_test(const std::string& algo,
              const std::string& key_str,
              const std::string& nonce_str,
              const std::string& header_str,
              const std::string& tag_str,
              const std::string& plaintext_str,
              const std::string& ciphertext)
   {
   /*
   printf("EAX(algo=%s key=%s nonce=%s header=%s tag=%s pt=%s ct=%s)\n",
          algo.c_str(), key_str.c_str(), nonce_str.c_str(), header_str.c_str(), tag_str.c_str(),
          plaintext_str.c_str(), ciphertext.c_str());
   */

   SymmetricKey key(key_str);
   InitializationVector iv(nonce_str);

   EAX_Encryption* enc;

   Pipe pipe(new Hex_Decoder,
             enc = new EAX_Encryption(get_block_cipher(algo)),
             new Hex_Encoder);

   enc->set_key(key);
   enc->set_iv(iv);

   OctetString header(header_str);

   enc->set_header(header.begin(), header.length());

   pipe.start_msg();
   pipe.write(plaintext_str);
   pipe.end_msg();

   std::string out = pipe.read_all_as_string();

   if(out != ciphertext + tag_str)
      {
      printf("BAD enc %s '%s' != '%s%s'\n", algo.c_str(),
             out.c_str(), ciphertext.c_str(), tag_str.c_str());
      }
   else
      printf("OK enc %s\n", algo.c_str());

   try
      {
      EAX_Decryption* dec;
      Pipe pipe2(new Hex_Decoder,
                 dec = new EAX_Decryption(get_block_cipher(algo)),
                 new Hex_Encoder);

      dec->set_key(key);
      dec->set_iv(iv);

      dec->set_header(header.begin(), header.length());

      pipe2.start_msg();
      pipe2.write(ciphertext);
      pipe2.write(tag_str);
      pipe2.end_msg();

      std::string out2 = pipe2.read_all_as_string();

      if(out2 != plaintext_str)
         {
         printf("BAD decrypt %s '%s'\n", algo.c_str(), out2.c_str());
         }
      else
         printf("OK decrypt %s\n", algo.c_str());
      }
   catch(std::exception& e)
      {
      printf("%s\n", e.what());
      }

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

   // Noekeon: unknown cause, though LTC's lone test vector does not
   // match Botan

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

void run_tests(std::istream& in)
   {
   std::string algo;
   std::string key;

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

            eax_test(algo, key, nonce, header, tag,
                     plaintext, ciphertext);

            key = rep(tag, key.size()); // repeat as needed
            }
         }
      }


   }

}

int main()
   {
   std::ifstream in("eax.vec");

   Botan::LibraryInitializer init;

   if(!in)
      {
      std::cerr << "Couldn't read input file\n";
      return 1;
      }

   run_tests(in);

   }
