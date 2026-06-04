/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"
#include <botan/hex.h>

#if defined(BOTAN_HAS_FPE_FE1) && defined(BOTAN_HAS_PBKDF)

   #include <botan/exceptn.h>
   #include <botan/fpe_fe1.h>
   #include <botan/pbkdf.h>
   #include <botan/symkey.h>
   #include <botan/internal/parsing.h>

namespace Botan_CLI {

namespace {

uint8_t luhn_checksum(uint64_t cc_number) {
   uint8_t sum = 0;

   bool alt = false;
   while(cc_number > 0) {
      uint8_t digit = cc_number % 10;
      if(alt) {
         digit *= 2;
         if(digit > 9) {
            digit -= 9;
         }
      }

      sum += digit;

      cc_number /= 10;
      alt = !alt;
   }

   return (sum % 10);
}

bool luhn_check(uint64_t cc_number) {
   return (luhn_checksum(cc_number) == 0);
}

uint64_t cc_rank(uint64_t cc_number) {
   // Remove Luhn checksum
   return cc_number / 10;
}

uint64_t cc_derank(uint64_t cc_number) {
   for(size_t i = 0; i != 10; ++i) {
      if(luhn_check(cc_number * 10 + i)) {
         return (cc_number * 10 + i);
      }
   }

   return 0;
}

uint64_t cc_modulus(size_t cc_digits) {
   uint64_t n = 1;
   for(size_t i = 1; i != cc_digits; ++i) {
      n *= 10;
   }
   return n;
}

uint64_t bigint_to_u64(const Botan::BigInt& n) {
   if(n.bits() > 64) {
      throw CLI_Error("FPE produced a number too large");
   }

   uint64_t result = 0;
   for(size_t i = 0; i != 8; ++i) {
      result = (result << 8) | n.byte_at(7 - i);
   }
   return result;
}

std::string format_cc_number(uint64_t cc_number, size_t cc_digits) {
   const std::string cc_str = std::to_string(cc_number);
   if(cc_str.size() > cc_digits) {
      throw CLI_Error("FPE produced a number too large");
   }
   return std::string(cc_digits - cc_str.size(), '0') + cc_str;
}

uint64_t encrypt_cc_number(uint64_t cc_number,
                           size_t cc_digits,
                           const Botan::SymmetricKey& key,
                           const std::vector<uint8_t>& tweak) {
   const Botan::BigInt n(cc_modulus(cc_digits));

   const Botan::BigInt c = Botan::FPE::fe1_encrypt(n, Botan::BigInt::from_u64(cc_rank(cc_number)), key, tweak);

   return cc_derank(bigint_to_u64(c));
}

uint64_t decrypt_cc_number(uint64_t enc_cc,
                           size_t cc_digits,
                           const Botan::SymmetricKey& key,
                           const std::vector<uint8_t>& tweak) {
   const Botan::BigInt n(cc_modulus(cc_digits));

   const Botan::BigInt c = Botan::FPE::fe1_decrypt(n, Botan::BigInt::from_u64(cc_rank(enc_cc)), key, tweak);

   return cc_derank(bigint_to_u64(c));
}

uint64_t parse_cc(std::string_view input) {
   if(input.size() >= 13 && input.size() <= 19) {
      if(auto cc = Botan::parse_u64(input)) {
         return *cc;
      }
   }

   throw CLI_Usage_Error("Invalid credit card input");
}

class CC_Encrypt final : public Command {
   public:
      CC_Encrypt() : Command("cc_encrypt CC passphrase --tweak=") {}

      std::string group() const override { return "misc"; }

      std::string description() const override {
         return "Encrypt the passed valid credit card number using FPE encryption";
      }

      void go() override {
         const std::string cc = get_arg("CC");
         const uint64_t cc_number = parse_cc(cc);
         const std::vector<uint8_t> tweak = Botan::hex_decode(get_arg("tweak"));
         const std::string pass = get_arg("passphrase");

         auto pbkdf = Botan::PBKDF::create("PBKDF2(SHA-256)");
         if(!pbkdf) {
            throw CLI_Error_Unsupported("PBKDF", "PBKDF2(SHA-256)");
         }

         auto key = Botan::SymmetricKey(pbkdf->pbkdf_iterations(32, pass, tweak.data(), tweak.size(), 100000));

         output() << format_cc_number(encrypt_cc_number(cc_number, cc.size(), key, tweak), cc.size()) << "\n";
      }
};

BOTAN_REGISTER_COMMAND("cc_encrypt", CC_Encrypt);

class CC_Decrypt final : public Command {
   public:
      CC_Decrypt() : Command("cc_decrypt CC passphrase --tweak=") {}

      std::string group() const override { return "misc"; }

      std::string description() const override {
         return "Decrypt the passed valid ciphertext credit card number using FPE decryption";
      }

      void go() override {
         const std::string cc = get_arg("CC");
         const uint64_t cc_number = parse_cc(cc);
         const std::vector<uint8_t> tweak = Botan::hex_decode(get_arg("tweak"));
         const std::string pass = get_arg("passphrase");

         auto pbkdf = Botan::PBKDF::create("PBKDF2(SHA-256)");
         if(!pbkdf) {
            throw CLI_Error_Unsupported("PBKDF", "PBKDF2(SHA-256)");
         }

         auto key = Botan::SymmetricKey(pbkdf->pbkdf_iterations(32, pass, tweak.data(), tweak.size(), 100000));

         output() << format_cc_number(decrypt_cc_number(cc_number, cc.size(), key, tweak), cc.size()) << "\n";
      }
};

BOTAN_REGISTER_COMMAND("cc_decrypt", CC_Decrypt);

}  // namespace

}  // namespace Botan_CLI

#endif  // FPE && PBKDF
