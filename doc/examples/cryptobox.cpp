/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/botan.h>
#include <botan/cryptobox.h>
#include <fstream>
#include <iostream>
#include <vector>

using namespace Botan;

int main(int argc, char* argv[])
   {
   LibraryInitializer init;

   AutoSeeded_RNG rng;

   if(argc != 3)
      {
      std::cout << "Usage: cryptobox pass filename\n";
      return 1;
      }

   std::string pass = argv[1];
   std::string filename = argv[2];

   std::ifstream input(filename.c_str(), std::ios::binary);

   std::vector<byte> file_contents;
   while(input.good())
      {
      byte filebuf[4096] = { 0 };
      input.read((char*)filebuf, sizeof(filebuf));
      size_t got = input.gcount();

      file_contents.insert(file_contents.end(), filebuf, filebuf+got);
      }

   std::string ciphertext = CryptoBox::encrypt(&file_contents[0],
                                               file_contents.size(),
                                               pass, rng);

   std::cout << ciphertext;

   /*
   std::cout << CryptoBox::decrypt((const byte*)&ciphertext[0],
                                   ciphertext.length(),
                                   pass);
   */
   }
