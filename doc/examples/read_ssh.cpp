/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

/*
* Example of reading SSH2 format public keys (see RFC 4716)
*/

#include <fstream>
#include <botan/x509_key.h>
#include <botan/filters.h>
#include <botan/loadstor.h>
#include <botan/rsa.h>
#include <botan/dsa.h>

using namespace Botan;

namespace {

u32bit read_u32bit(Pipe& pipe)
   {
   byte out[4] = { 0 };
   pipe.read(out, 4);
   u32bit len = load_be<u32bit>(out, 0);
   if(len > 10000)
      throw Decoding_Error("Huge size in read_u32bit, something went wrong");
   return len;
   }

std::string read_string(Pipe& pipe)
   {
   u32bit len = read_u32bit(pipe);

   std::string out(len, 'X');
   pipe.read(reinterpret_cast<byte*>(&out[0]), len);
   return out;
   }

BigInt read_bigint(Pipe& pipe)
   {
   u32bit len = read_u32bit(pipe);

   SecureVector<byte> buf(len);
   pipe.read(&buf[0], len);
   return BigInt::decode(buf);
   }

Public_Key* read_ssh_pubkey(const std::string& file)
   {
   std::ifstream in(file.c_str());

   const std::string ssh_header = "---- BEGIN SSH2 PUBLIC KEY ----";
   const std::string ssh_trailer = "---- END SSH2 PUBLIC KEY ----";

   std::string hex_bits;

   std::string line;
   std::getline(in, line);

   if(line != ssh_header)
      return 0;

   while(in.good())
      {
      std::getline(in, line);

      if(line.find("Comment: ") == 0)
         {
         while(line[line.size()-1] == '\\')
            std::getline(in, line);
         std::getline(in, line);
         }

      if(line == ssh_trailer)
         break;

      hex_bits += line;
      }

   Pipe pipe(new Base64_Decoder);
   pipe.process_msg(hex_bits);

   std::string key_type = read_string(pipe);

   if(key_type != "ssh-rsa" && key_type != "ssh-dss")
      return 0;

   if(key_type == "ssh-rsa")
      {
      BigInt e = read_bigint(pipe);
      BigInt n = read_bigint(pipe);
      return new RSA_PublicKey(n, e);
      }
   else if(key_type == "ssh-dss")
      {
      BigInt p = read_bigint(pipe);
      BigInt q = read_bigint(pipe);
      BigInt g = read_bigint(pipe);
      BigInt y = read_bigint(pipe);

      return new DSA_PublicKey(DL_Group(p, q, g), y);
      }

   return 0;
   }

}

#include <botan/init.h>
#include <iostream>

int main()
   {
   LibraryInitializer init;

   Public_Key* key = read_ssh_pubkey("dsa.ssh");

   if(key == 0)
      {
      std::cout << "Failed\n";
      return 1;
      }

   std::cout << X509::PEM_encode(*key);

   delete key;

   return 0;
   }
