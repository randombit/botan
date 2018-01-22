/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"
#include <botan/hex.h>

#if defined(BOTAN_HAS_FPE_FE1) && defined(BOTAN_HAS_PBKDF)

#include <botan/fpe_fe1.h>
#include <botan/pbkdf.h>

namespace Botan_CLI {

namespace {

uint8_t luhn_checksum(uint64_t cc_number)
   {
   uint8_t sum = 0;

   bool alt = false;
   while(cc_number)
      {
      uint8_t digit = cc_number % 10;
      if(alt)
         {
         digit *= 2;
         if(digit > 9)
            {
            digit -= 9;
            }
         }

      sum += digit;

      cc_number /= 10;
      alt = !alt;
      }

   return (sum % 10);
   }

bool luhn_check(uint64_t cc_number)
   {
   return (luhn_checksum(cc_number) == 0);
   }

uint64_t cc_rank(uint64_t cc_number)
   {
   // Remove Luhn checksum
   return cc_number / 10;
   }

uint64_t cc_derank(uint64_t cc_number)
   {
   for(size_t i = 0; i != 10; ++i)
      {
      if(luhn_check(cc_number * 10 + i))
         {
         return (cc_number * 10 + i);
         }
      }

   return 0;
   }

uint64_t encrypt_cc_number(uint64_t cc_number,
                           const Botan::secure_vector<uint8_t>& key,
                           const std::vector<uint8_t>& tweak)
   {
   const Botan::BigInt n = 1000000000000000;

   const uint64_t cc_ranked = cc_rank(cc_number);

   const Botan::BigInt c = Botan::FPE::fe1_encrypt(n, cc_ranked, key, tweak);

   if(c.bits() > 50)
      {
      throw Botan::Internal_Error("FPE produced a number too large");
      }

   uint64_t enc_cc = 0;
   for(size_t i = 0; i != 7; ++i)
      {
      enc_cc = (enc_cc << 8) | c.byte_at(6 - i);
      }
   return cc_derank(enc_cc);
   }

uint64_t decrypt_cc_number(uint64_t enc_cc,
                           const Botan::secure_vector<uint8_t>& key,
                           const std::vector<uint8_t>& tweak)
   {
   const Botan::BigInt n = 1000000000000000;

   const uint64_t cc_ranked = cc_rank(enc_cc);

   const Botan::BigInt c = Botan::FPE::fe1_decrypt(n, cc_ranked, key, tweak);

   if(c.bits() > 50)
      {
      throw CLI_Error("FPE produced a number too large");
      }

   uint64_t dec_cc = 0;
   for(size_t i = 0; i != 7; ++i)
      {
      dec_cc = (dec_cc << 8) | c.byte_at(6 - i);
      }
   return cc_derank(dec_cc);
   }

}

class CC_Encrypt final : public Command
   {
   public:
      CC_Encrypt() : Command("cc_encrypt CC passphrase --tweak=") {}

      std::string group() const override
         {
         return "misc";
         }

      std::string description() const override
         {
         return "Encrypt the passed valid credit card number using FPE encryption";
         }

      void go() override
         {
         const uint64_t cc_number = std::stoull(get_arg("CC"));
         const std::vector<uint8_t> tweak = Botan::hex_decode(get_arg("tweak"));
         const std::string pass = get_arg("passphrase");

         std::unique_ptr<Botan::PBKDF> pbkdf(Botan::PBKDF::create("PBKDF2(SHA-256)"));
         if(!pbkdf)
            {
            throw CLI_Error_Unsupported("PBKDF", "PBKDF2(SHA-256)");
            }

         Botan::secure_vector<uint8_t> key = pbkdf->pbkdf_iterations(32, pass, tweak.data(), tweak.size(), 100000);

         output() << encrypt_cc_number(cc_number, key, tweak) << "\n";
         }
   };

BOTAN_REGISTER_COMMAND("cc_encrypt", CC_Encrypt);

class CC_Decrypt final : public Command
   {
   public:
      CC_Decrypt() : Command("cc_decrypt CC passphrase --tweak=") {}

      std::string group() const override
         {
         return "misc";
         }

      std::string description() const override
         {
         return "Decrypt the passed valid ciphertext credit card number using FPE decryption";
         }

      void go() override
         {
         const uint64_t cc_number = std::stoull(get_arg("CC"));
         const std::vector<uint8_t> tweak = Botan::hex_decode(get_arg("tweak"));
         const std::string pass = get_arg("passphrase");

         std::unique_ptr<Botan::PBKDF> pbkdf(Botan::PBKDF::create("PBKDF2(SHA-256)"));
         if(!pbkdf)
            {
            throw CLI_Error_Unsupported("PBKDF", "PBKDF2(SHA-256)");
            }

         Botan::secure_vector<uint8_t> key = pbkdf->pbkdf_iterations(32, pass, tweak.data(), tweak.size(), 100000);

         output() << decrypt_cc_number(cc_number, key, tweak) << "\n";
         }
   };

BOTAN_REGISTER_COMMAND("cc_decrypt", CC_Decrypt);

}

#endif // FPE && PBKDF
