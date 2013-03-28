
#include "validate.h"

#include <botan/ocb.h>
#include <botan/hex.h>
#include <botan/sha2_32.h>
#include <botan/aes.h>
#include <iostream>
//#include <botan/selftest.h>

using namespace Botan;

// something like this should be in the library
std::vector<byte> ocb_encrypt(const SymmetricKey& key,
                              const std::vector<byte>& nonce,
                              const byte pt[], size_t pt_len,
                              const byte ad[], size_t ad_len)
   {
   //std::unique_ptr<AEAD_Mode> ocb = get_aead("AES-128/OCB", ENCRYPTION);

   OCB_Encryption ocb(new AES_128);

   ocb.set_key(key);
   ocb.set_associated_data(ad, ad_len);

   ocb.start(&nonce[0], nonce.size());

   secure_vector<byte> buf(pt, pt+pt_len);
   ocb.update(buf, 0);
   ocb.finish(buf, buf.size());
   //ocb.finish(buf);

   return unlock(buf);
   }

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
   ocb.update(buf, 0);
   ocb.finish(buf, buf.size());
   //ocb.finish(buf);

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

void test_ocb_long_filters()
   {
   SymmetricKey key("00000000000000000000000000000000");

   OCB_Encryption ocb(new AES_128);

   ocb.set_key(key);

   const std::vector<byte> empty;
   std::vector<byte> N(12);
   std::vector<byte> C;

   for(size_t i = 0; i != 128; ++i)
      {
      const std::vector<byte> S(i);
      N[11] = i;

      const std::vector<byte> C1 = ocb_encrypt(ocb, N, S, S);
      const std::vector<byte> C2 = ocb_encrypt(ocb, N, S, empty);
      const std::vector<byte> C3 = ocb_encrypt(ocb, N, empty, S);

      //std::cout << "C_" << i << " = " << hex_encode(C1) << " " << hex_encode(C2) << " " << hex_encode(C3) << "\n";

      C += C1;
      C += C2;
      C += C3;
      }

   SHA_256 sha256;
   sha256.update(C);
   const std::string C_hash = hex_encode(sha256.final());
   const std::string expected_C_hash = "C4E5158067F49356042296B13B050DE00A120EA846073E5E0DACFD0C9F43CC65";

   if(C_hash != expected_C_hash)
      {
      std::cout << "OCB-128 long test, C hashes differ\n";
      std::cout << C_hash << " !=\n" << expected_C_hash << "\n";
      }

   //std::cout << "SHA-256(C) = " << C_hash << "\n";

   N[11] = 0;
   const std::vector<byte> cipher = ocb_encrypt(ocb, N, empty, C);

   const std::string expected = "B2B41CBF9B05037DA7F16C24A35C1C94";

   const std::string cipher_hex = hex_encode(cipher);

   if(cipher_hex != expected)
      std::cout << "OCB AES-128 long test mistmatch " << cipher_hex << " != " << expected << "\n";
   else
      std::cout << "OCB AES-128 long test OK\n";
   }

void test_ocb_long()
   {
   SymmetricKey key("00000000000000000000000000000000");

   const std::vector<byte> empty;
   std::vector<byte> N(12);
   std::vector<byte> C;

   for(size_t i = 0; i != 128; ++i)
      {
      const std::vector<byte> S(i);
      N[11] = i;

      const std::vector<byte> C1 = ocb_encrypt(key, N, S, S);
      const std::vector<byte> C2 = ocb_encrypt(key, N, S, empty);
      const std::vector<byte> C3 = ocb_encrypt(key, N, empty, S);

      //std::cout << "C_" << i << " = " << hex_encode(C1) << " " << hex_encode(C2) << " " << hex_encode(C3) << "\n";

      C += C1;
      C += C2;
      C += C3;

      SHA_256 sha256;
      sha256.update(C);
      //std::cout << "SHA-256(C_" << i << ") = " << hex_encode(sha256.final()) << "\n";
      }

   // SHA-256 hash of C would be useful

   SHA_256 sha256;
   sha256.update(C);
   const std::string C_hash = hex_encode(sha256.final());
   const std::string expected_C_hash = "C4E5158067F49356042296B13B050DE00A120EA846073E5E0DACFD0C9F43CC65";

   if(C_hash != expected_C_hash)
      {
      std::cout << "OCB-128 long test, C hashes differ\n";
      std::cout << C_hash << " !=\n" << expected_C_hash << "\n";
      }

   //std::cout << "SHA-256(C) = " << C_hash << "\n";

   N[11] = 0;
   const std::vector<byte> cipher = ocb_encrypt(key, N, empty, C);

   const std::string expected = "B2B41CBF9B05037DA7F16C24A35C1C94";

   const std::string cipher_hex = hex_encode(cipher);

   if(cipher_hex != expected)
      std::cout << "OCB AES-128 long test mistmatch " << cipher_hex << " != " << expected << "\n";
   else
      std::cout << "OCB AES-128 long test OK\n";

   try
      {
      const std::vector<byte> p = ocb_decrypt(key, N, cipher, C);

      BOTAN_ASSERT(p.empty(), "return plaintext is empty");
      }
   catch(std::exception& e)
      {
      std::cout << "Error in OCB decrypt - " << e.what() << "\n";
      }

   try
      {
      C[0] ^= 1;
      ocb_decrypt(key, N, cipher, C);
      std::cout << "OCB failed to reject bad message\n";
      }
   catch(std::exception& e)
      {
      }


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

   //test_ocb_long();
   test_ocb_long_filters();
   }


