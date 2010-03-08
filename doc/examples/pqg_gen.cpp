/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <memory>

#include <botan/botan.h>
#include <botan/auto_rng.h>
#include <botan/dsa.h>
#include <botan/numthry.h>
#include <botan/dl_group.h>
using namespace Botan;

bool check(RandomNumberGenerator& rng,
           std::map<std::string, std::string>);

int main()
   {
   try {
       Botan::LibraryInitializer init("use_engines");

      AutoSeeded_RNG rng;

      std::ifstream in("PQGGen.rsp");
      if(!in)
         throw std::runtime_error("Can't open response file");

      std::map<std::string, std::string> inputs;

      while(in.good())
         {
         std::string line;
         std::getline(in, line);

         if(line == "" || line[0] == '[' || line[0] == '#')
            continue;

         std::vector<std::string> name_and_val = split_on(line, '=');

         if(name_and_val.size() != 2)
            throw std::runtime_error("Unexpected input: " + line);

         name_and_val[0].erase(name_and_val[0].size()-1);
         name_and_val[1].erase(0, 1);

         std::string name = name_and_val[0], value = name_and_val[1];

         inputs[name] = value;

         if(name == "H")
            {
            bool result = check(rng, inputs);
            std::cout << "." << std::flush;
            if(result == false)
               {
               std::cout << "   Check failed\n";

               std::map<std::string, std::string>::const_iterator i;

               for(i = inputs.begin(); i != inputs.end(); i++)
                  std::cout << i->first << " = " << i->second << "\n";

               std::cout << "\n";
               }

            inputs.clear();
            }
         }
   }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }
   return 0;
   }

bool check(RandomNumberGenerator& rng,
           std::map<std::string, std::string> inputs)
   {
   BigInt p("0x"+inputs["P"]),
          q("0x"+inputs["Q"]),
          g("0x"+inputs["G"]),
          h("0x"+inputs["H"]);

   if(h < 1 || h >= p-1) return false;

   //u32bit c = to_u32bit(inputs["c"]);

   Pipe pipe(new Hex_Decoder);
   pipe.process_msg(inputs["Seed"]);
   SecureVector<byte> seed = pipe.read_all();

   BigInt our_p, our_q;

   u32bit qbits = (p.bits() <= 1024) ? 160 : 256;

   Algorithm_Factory& af = global_state().algorithm_factory();

   bool found = generate_dsa_primes(rng, af, our_p, our_q,
                                    p.bits(), qbits, seed);

   if(!found) /* bad seed */
      return false;

   if(our_p != p) return false;
   if(our_q != q) return false;

   BigInt our_g = power_mod(h, (p-1)/q, p);

   if(our_g != g) return false;

   return true;
   }
