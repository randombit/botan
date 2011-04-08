/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/botan.h>
#include <botan/serpent.h>
#include <botan/package.h>

#include <iostream>
#include <fstream>
#include <vector>

using namespace Botan;

namespace {

std::vector<byte> slurp_file(const std::string& filename)
   {
     std::ifstream in(filename.c_str(), std::ios::binary);

   std::vector<byte> out;
   byte buf[4096] = { 0 };

   while(in.good())
      {
      in.read((char*)buf, sizeof(buf));
      ssize_t got = in.gcount();

      out.insert(out.end(), buf, buf+got);
      }

   return out;
   }

}

int main(int argc, char* argv[])
   {
   if(argc != 2)
      {
      std::cout << "Usage: " << argv[0] << " filename\n";
      return 1;
      }

   LibraryInitializer init;

   AutoSeeded_RNG rng;

   BlockCipher* cipher = new Serpent;

   std::vector<byte> input = slurp_file(argv[1]);
   std::vector<byte> output(input.size() + cipher->block_size());

   aont_package(rng, new Serpent,
                &input[0], input.size(),
                &output[0]);

   std::vector<byte> unpackage_output(output.size() - cipher->block_size());

   aont_unpackage(new Serpent,
                  &output[0], output.size(),
                  &unpackage_output[0]);

   if(unpackage_output == input)
      std::cout << "Package/unpackage worked\n";
   else
      std::cout << "Something went wrong :(\n";
   }
