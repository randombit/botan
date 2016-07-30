/*
* Hash Function Identification
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hash_id.h>
#include <botan/exceptn.h>

namespace Botan {

namespace {

const byte MD2_PKCS_ID[] = {
0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86,
0xF7, 0x0D, 0x02, 0x02, 0x05, 0x00, 0x04, 0x10 };

const byte MD5_PKCS_ID[] = {
0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86,
0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };

const byte RIPEMD_128_PKCS_ID[] = {
0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24, 0x03, 0x02,
0x02, 0x05, 0x00, 0x04, 0x14 };

const byte RIPEMD_160_PKCS_ID[] = {
0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24, 0x03, 0x02,
0x01, 0x05, 0x00, 0x04, 0x14 };

const byte SHA_160_PKCS_ID[] = {
0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02,
0x1A, 0x05, 0x00, 0x04, 0x14 };

const byte SHA_224_PKCS_ID[] = {
0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1C };

const byte SHA_256_PKCS_ID[] = {
0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

const byte SHA_384_PKCS_ID[] = {
0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 };

const byte SHA_512_PKCS_ID[] = {
0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };

const byte SHA_512_256_PKCS_ID[] = {
0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
0x65, 0x03, 0x04, 0x02, 0x06, 0x05, 0x00, 0x04, 0x20 };

const byte TIGER_PKCS_ID[] = {
0x30, 0x29, 0x30, 0x0D, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04,
0x01, 0xDA, 0x47, 0x0C, 0x02, 0x05, 0x00, 0x04, 0x18 };

}

/*
* HashID as specified by PKCS
*/
std::vector<byte> pkcs_hash_id(const std::string& name)
   {
   // Special case for SSL/TLS RSA signatures
   if(name == "Parallel(MD5,SHA-160)")
      return std::vector<byte>();

   if(name == "MD2")
      return std::vector<byte>(MD2_PKCS_ID,
                               MD2_PKCS_ID + sizeof(MD2_PKCS_ID));

   if(name == "MD5")
      return std::vector<byte>(MD5_PKCS_ID,
                               MD5_PKCS_ID + sizeof(MD5_PKCS_ID));

   if(name == "RIPEMD-128")
      return std::vector<byte>(RIPEMD_128_PKCS_ID,
                               RIPEMD_128_PKCS_ID + sizeof(RIPEMD_128_PKCS_ID));

   if(name == "RIPEMD-160")
      return std::vector<byte>(RIPEMD_160_PKCS_ID,
                               RIPEMD_160_PKCS_ID + sizeof(RIPEMD_160_PKCS_ID));

   if(name == "SHA-160")
      return std::vector<byte>(SHA_160_PKCS_ID,
                               SHA_160_PKCS_ID + sizeof(SHA_160_PKCS_ID));

   if(name == "SHA-224")
      return std::vector<byte>(SHA_224_PKCS_ID,
                               SHA_224_PKCS_ID + sizeof(SHA_224_PKCS_ID));

   if(name == "SHA-256")
      return std::vector<byte>(SHA_256_PKCS_ID,
                               SHA_256_PKCS_ID + sizeof(SHA_256_PKCS_ID));

   if(name == "SHA-384")
      return std::vector<byte>(SHA_384_PKCS_ID,
                               SHA_384_PKCS_ID + sizeof(SHA_384_PKCS_ID));

   if(name == "SHA-512")
      return std::vector<byte>(SHA_512_PKCS_ID,
                               SHA_512_PKCS_ID + sizeof(SHA_512_PKCS_ID));

   if(name == "SHA-512-256")
      return std::vector<byte>(SHA_512_256_PKCS_ID,
                               SHA_512_256_PKCS_ID + sizeof(SHA_512_256_PKCS_ID));

   if(name == "Tiger(24,3)")
      return std::vector<byte>(TIGER_PKCS_ID,
                               TIGER_PKCS_ID + sizeof(TIGER_PKCS_ID));

   throw Invalid_Argument("No PKCS #1 identifier for " + name);
   }

/*
* HashID as specified by IEEE 1363/X9.31
*/
byte ieee1363_hash_id(const std::string& name)
   {
   if(name == "SHA-160")    return 0x33;

   if(name == "SHA-224")    return 0x38;
   if(name == "SHA-256")    return 0x34;
   if(name == "SHA-384")    return 0x36;
   if(name == "SHA-512")    return 0x35;

   if(name == "RIPEMD-160") return 0x31;
   if(name == "RIPEMD-128") return 0x32;

   if(name == "Whirlpool")  return 0x37;

   return 0;
   }

}
