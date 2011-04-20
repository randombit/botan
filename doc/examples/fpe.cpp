#include <botan/botan.h>
#include <botan/fpe_fe1.h>
#include <botan/sha160.h>

using namespace Botan;

#include <iostream>
#include <stdexcept>

namespace {

byte luhn_checksum(u64bit cc_number)
   {
   byte sum = 0;

   bool alt = false;
   while(cc_number)
      {
      byte digit = cc_number % 10;
      if(alt)
         {
         digit *= 2;
         if(digit > 9)
            digit -= 9;
         }

      sum += digit;

      cc_number /= 10;
      alt = !alt;
      }

   return (sum % 10);
   }

bool luhn_check(u64bit cc_number)
   {
   return (luhn_checksum(cc_number) == 0);
   }

u64bit cc_rank(u64bit cc_number)
   {
   // Remove Luhn checksum
   return cc_number / 10;
   }

u64bit cc_derank(u64bit cc_number)
   {
   for(u32bit i = 0; i != 10; ++i)
      if(luhn_check(cc_number * 10 + i))
         return (cc_number * 10 + i);
   return 0;
   }

/*
* Use the SHA-1 hash of the account name or ID as a tweak
*/
SecureVector<byte> sha1(const std::string& acct_name)
   {
   SHA_160 hash;
   hash.update(acct_name);
   return hash.final();
   }

u64bit encrypt_cc_number(u64bit cc_number,
                         const SymmetricKey& key,
                         const std::string& acct_name)
   {
   BigInt n = 1000000000000000;

   u64bit cc_ranked = cc_rank(cc_number);

   BigInt c = FPE::fe1_encrypt(n, cc_ranked, key, sha1(acct_name));

   if(c.bits() > 50)
      throw std::runtime_error("FPE produced a number too large");

   u64bit enc_cc = 0;
   for(u32bit i = 0; i != 7; ++i)
      enc_cc = (enc_cc << 8) | c.byte_at(6-i);
   return cc_derank(enc_cc);
   }

u64bit decrypt_cc_number(u64bit enc_cc,
                         const SymmetricKey& key,
                         const std::string& acct_name)
   {
   BigInt n = 1000000000000000;

   u64bit cc_ranked = cc_rank(enc_cc);

   BigInt c = FPE::fe1_decrypt(n, cc_ranked, key, sha1(acct_name));

   if(c.bits() > 50)
      throw std::runtime_error("FPE produced a number too large");

   u64bit dec_cc = 0;
   for(u32bit i = 0; i != 7; ++i)
      dec_cc = (dec_cc << 8) | c.byte_at(6-i);
   return cc_derank(dec_cc);
   }

}

int main(int argc, char* argv[])
   {
   LibraryInitializer init;

   if(argc != 4)
      {
      std::cout << "Usage: " << argv[0] << " cc-number acct-name passwd\n";
      return 1;
      }

   u64bit cc_number = atoll(argv[1]);
   std::string acct_name = argv[2];
   std::string passwd = argv[3];

   std::cout << "Input was: " << cc_number << ' '
             << luhn_check(cc_number) << '\n';

   /*
   * In practice something like PBKDF2 with a salt and high iteration
   * count would be a good idea.
   */
   SymmetricKey key = sha1(passwd);

   u64bit enc_cc = encrypt_cc_number(cc_number, key, acct_name);

   std::cout << "Encrypted: " << enc_cc
             << ' ' << luhn_check(enc_cc) << '\n';

   u64bit dec_cc = decrypt_cc_number(enc_cc, key, acct_name);

   std::cout << "Decrypted: " << dec_cc
             << ' ' << luhn_check(dec_cc) << '\n';

   if(dec_cc != cc_number)
      std::cout << "Something went wrong :( Bad CC checksum?\n";
   }
