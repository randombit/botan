
#include "validate.h"

#include <botan/ocb.h>
#include <botan/hex.h>
#include <botan/sha2_32.h>
#include <botan/aes.h>
#include <iostream>
//#include <botan/selftest.h>

using namespace Botan;

// something like this should be in the library

std::vector<byte> ocb_decrypt(const SymmetricKey& key,
                              const std::vector<byte>& nonce,
                              const byte ct[], size_t ct_len,
                              const byte ad[], size_t ad_len)
   {
   OCB_Decryption ocb(new AES_128);

   ocb.set_key(key);
   ocb.set_associated_data(ad, ad_len);

   ocb.start(&nonce[0], nonce.size());

   secure_vector<byte> buf(ct, ct+ct_len);
   ocb.finish(buf, 0);

   return unlock(buf);
   }

std::vector<byte> ocb_encrypt(const SymmetricKey& key,
                              const std::vector<byte>& nonce,
                              const byte pt[], size_t pt_len,
                              const byte ad[], size_t ad_len)
   {
   OCB_Encryption ocb(new AES_128);

   ocb.set_key(key);
   ocb.set_associated_data(ad, ad_len);

   ocb.start(&nonce[0], nonce.size());

   secure_vector<byte> buf(pt, pt+pt_len);
   ocb.finish(buf, 0);

   try
      {
      std::vector<byte> pt2 = ocb_decrypt(key, nonce, &buf[0], buf.size(), ad, ad_len);
      if(pt_len != pt2.size() || !same_mem(pt, &pt2[0], pt_len))
         std::cout << "OCB failed to decrypt correctly\n";
      }
   catch(std::exception& e)
      {
      std::cout << "OCB round trip error - " << e.what() << "\n";
      }

   return unlock(buf);
   }

template<typename Alloc, typename Alloc2>
std::vector<byte> ocb_encrypt(const SymmetricKey& key,
                              const std::vector<byte>& nonce,
                              const std::vector<byte, Alloc>& pt,
                              const std::vector<byte, Alloc2>& ad)
   {
   return ocb_encrypt(key, nonce, &pt[0], pt.size(), &ad[0], ad.size());
   }

template<typename Alloc, typename Alloc2>
std::vector<byte> ocb_decrypt(const SymmetricKey& key,
                              const std::vector<byte>& nonce,
                              const std::vector<byte, Alloc>& pt,
                              const std::vector<byte, Alloc2>& ad)
   {
   return ocb_decrypt(key, nonce, &pt[0], pt.size(), &ad[0], ad.size());
   }

std::vector<byte> ocb_encrypt(OCB_Encryption& ocb,
                              const std::vector<byte>& nonce,
                              const std::vector<byte>& pt,
                              const std::vector<byte>& ad)
   {
   ocb.set_associated_data(&ad[0], ad.size());

   ocb.start(&nonce[0], nonce.size());

   secure_vector<byte> buf(pt.begin(), pt.end());
   ocb.finish(buf, 0);

   return unlock(buf);
   }

void test_ocb_long(size_t taglen, const std::string &expected)
   {
   OCB_Encryption ocb(new AES_128, taglen/8);

   ocb.set_key(SymmetricKey("00000000000000000000000000000000"));

   const std::vector<byte> empty;
   std::vector<byte> N(12);
   std::vector<byte> C;

   for(size_t i = 0; i != 128; ++i)
      {
      const std::vector<byte> S(i);
      N[11] = i;

      C += ocb_encrypt(ocb, N, S, S);
      C += ocb_encrypt(ocb, N, S, empty);
      C += ocb_encrypt(ocb, N, empty, S);
      }

   N[11] = 0;
   const std::vector<byte> cipher = ocb_encrypt(ocb, N, empty, C);

   const std::string cipher_hex = hex_encode(cipher);

   if(cipher_hex != expected)
      std::cout << "OCB AES-128 long test mistmatch " << cipher_hex << " != " << expected << "\n";
   else
      std::cout << "OCB AES-128 long test OK\n";
   }

void test_ocb()
   {
   SymmetricKey key("000102030405060708090A0B0C0D0E0F");

   std::vector<byte> nonce = hex_decode("000102030405060708090A0B");

   std::vector<byte> pt = hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627");
   std::vector<byte> ad = hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627");

   const std::string expected = "BEA5E8798DBE7110031C144DA0B26122CEAAB9B05DF771A657149D53773463CB68C65778B058A635659C623211DEEA0DE30D2C381879F4C8";

   std::vector<byte> ctext = ocb_encrypt(key, nonce, pt, ad);

   const std::string ctext_hex = hex_encode(ctext);

   if(ctext_hex != expected)
      std::cout << "OCB/AES-128 encrypt test failure\n" << ctext_hex << " !=\n" << expected << "\n";
   else
      std::cout << "OCB/AES-128 encrypt OK\n";

   try
      {
      std::vector<byte> dec = ocb_decrypt(key, nonce, ctext, ad);

      if(dec == pt) { std::cout << "OCB decrypts OK\n"; }
      else { std::cout << "OCB fails to decrypt\n"; }
      }
   catch(std::exception& e)
      {
      std::cout << "Correct OCB message rejected - " << e.what() << "\n";
      }

   test_ocb_long(128, "B2B41CBF9B05037DA7F16C24A35C1C94");
   test_ocb_long(96, "1A4F0654277709A5BDA0D380");
   test_ocb_long(64, "B7ECE9D381FE437F");
   }


