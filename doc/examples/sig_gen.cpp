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
#include <botan/dsa.h>
#include <botan/pubkey.h>
using namespace Botan;

bool check(std::map<std::string, std::string>);

int main()
   {
   try {
       Botan::LibraryInitializer init;

      std::ifstream in("SigGen.rsp");
      if(!in)
         throw Exception("Can't open response file");

      std::map<std::string, std::string> inputs;

      while(in.good())
         {
         std::string line;
         std::getline(in, line);

         if(line == "" || line[0] == '[' || line[0] == '#')
            continue;

         std::vector<std::string> name_and_val = split_on(line, '=');

         if(name_and_val.size() != 2)
            throw Decoding_Error("Unexpected input: " + line);

         name_and_val[0].erase(name_and_val[0].size()-1);
         name_and_val[1].erase(0, 1);

         std::string name = name_and_val[0], value = name_and_val[1];

         inputs[name] = value;

         if(name == "S")
            {
            bool result = check(inputs);
            if(result == false)
               {
               std::cout << "   Check failed\n";

               std::map<std::string, std::string>::const_iterator i;

               for(i = inputs.begin(); i != inputs.end(); i++)
                  std::cout << i->first << " = " << i->second << "\n";
               }
            inputs["Msg"] = inputs["R"] = inputs["S"] = "";
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

bool check(std::map<std::string, std::string> inputs)
   {
   BigInt p("0x"+inputs["P"]),
          q("0x"+inputs["Q"]),
          g("0x"+inputs["G"]),
          y("0x"+inputs["Y"]);

   DSA_PublicKey key(DL_Group(p, q, g), y);

   Pipe pipe(new Hex_Decoder);

   pipe.process_msg(inputs["Msg"]);
   pipe.start_msg();
   pipe.write(inputs["R"]);
   pipe.write(inputs["S"] );
   pipe.end_msg();

   PK_Verifier verifier(key, "EMSA1(SHA-1)");

   return verifier.verify_message(pipe.read_all(0), pipe.read_all(1));
   }
