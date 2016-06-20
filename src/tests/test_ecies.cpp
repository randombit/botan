/*
* (C) 2016 Philipp Weber
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"


#if defined(BOTAN_HAS_ECIES)
   #include "test_pubkey.h"
   #include <botan/ecies.h>
   #include <botan/ecdh.h>
   #include <botan/auto_rng.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECIES)

using byte = Botan::byte;
using Flags = Botan::ECIES_Flags;

Botan::PointGFp::Compression_Type get_compression_type(const std::string& format)
   {
   if(format == "uncompressed")
      {
      return Botan::PointGFp::UNCOMPRESSED;
      }
   else if(format == "compressed")
      {
      return Botan::PointGFp::COMPRESSED;
      }
   else if(format == "hybrid")
      {
      return Botan::PointGFp::HYBRID;
      }
   throw Botan::Invalid_Argument("invalid compression format");
   }

Flags ecies_flags(bool cofactor_mode, bool old_cofactor_mode, bool check_mode, bool single_hash_mode)
   {
   return (cofactor_mode ? Flags::COFACTOR_MODE : Flags::NONE)
          | (single_hash_mode ? Flags::SINGLE_HASH_MODE : Flags::NONE)
          | (old_cofactor_mode ? Flags::OLD_COFACTOR_MODE : Flags::NONE)
          | (check_mode ? Flags::CHECK_MODE : Flags::NONE);
   }

void check_encrypt_decrypt(Test::Result& result, const Botan::ECDH_PrivateKey& private_key,
                           const Botan::ECDH_PrivateKey& other_private_key,
                           const Botan::ECIES_System_Params& ecies_params,
                           const Botan::InitializationVector& iv, const std::string& label,
                           const std::vector<byte>& plaintext, const std::vector<byte>& ciphertext)
   {
   Botan::ECIES_Encryptor ecies_enc(private_key, ecies_params);
   ecies_enc.set_other_key(other_private_key.public_point());
   Botan::ECIES_Decryptor ecies_dec(other_private_key, ecies_params);
   if(!iv.bits_of().empty())
      {
      ecies_enc.set_initialization_vector(iv);
      ecies_dec.set_initialization_vector(iv);
      }
   if(!label.empty())
      {
      ecies_enc.set_label(label);
      ecies_dec.set_label(label);
      }

   try
      {
      const std::vector<byte> encrypted = ecies_enc.encrypt(plaintext, Test::rng());
      if(!ciphertext.empty())
         {
         result.test_eq("encrypted data", encrypted, ciphertext);
         }
      const Botan::secure_vector<byte> decrypted = ecies_dec.decrypt(encrypted);
      result.test_eq("decrypted data equals plaintext", decrypted, plaintext);
	  
      std::vector<byte> invalid_encrypted = encrypted;
      byte& last_byte = invalid_encrypted[invalid_encrypted.size() - 1];
      last_byte = ~last_byte;
      result.test_throws("throw on invalid ciphertext", [&ecies_dec, &invalid_encrypted]
         {
         ecies_dec.decrypt(invalid_encrypted);
         });
      }
   catch(Botan::Lookup_Error& e)
      {
      result.test_note(std::string("Test not executed: ") + e.what());
      }
   }

void check_encrypt_decrypt(Test::Result& result, const Botan::ECDH_PrivateKey& private_key,
                           const Botan::ECDH_PrivateKey& other_private_key,
                           const Botan::ECIES_System_Params& ecies_params, size_t iv_length = 0)
   {
   const std::vector<byte> plaintext { 1, 2, 3 };
   check_encrypt_decrypt(result, private_key, other_private_key, ecies_params, std::vector<byte>(iv_length, 0), "",
                         plaintext, std::vector<byte>());
   }

class ECIES_ISO_Tests : public Text_Based_Test
   {
   public:
      ECIES_ISO_Tests() : Text_Based_Test(
            "pubkey/ecies-18033.vec",
         { "format", "p", "a", "b", "mu", "nu", "gx", "gy", "hx", "hy", "x", "r", "C0", "K" })
         {
         }

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("ECIES-ISO");

         // get test vectors defined by ISO 18033
         const Botan::PointGFp::Compression_Type compression_type = get_compression_type(get_req_str(vars, "format"));
         const Botan::BigInt p = get_req_bn(vars, "p");
         const Botan::BigInt a = get_req_bn(vars, "a");
         const Botan::BigInt b = get_req_bn(vars, "b");
         const Botan::BigInt mu = get_req_bn(vars, "mu");	// order
         const Botan::BigInt nu = get_req_bn(vars, "nu");	// cofactor
         const Botan::BigInt gx = get_req_bn(vars, "gx");	// base point x
         const Botan::BigInt gy = get_req_bn(vars, "gy");	// base point y
         const Botan::BigInt hx = get_req_bn(vars, "hx");	// x of public point of bob
         const Botan::BigInt hy = get_req_bn(vars, "hy");	// y of public point of bob
         const Botan::BigInt x = get_req_bn(vars, "x");	// private key of bob
         const Botan::BigInt r = get_req_bn(vars, "r");	// (ephemeral) private key of alice
         const std::vector<byte> c0 = get_req_bin(vars, "C0");	// expected encoded (ephemeral) public key
         const std::vector<byte> k = get_req_bin(vars, "K");	// expected derived secret

         const Botan::CurveGFp curve(p, a, b);
         const Botan::EC_Group domain(curve, Botan::PointGFp(curve, gx, gy), mu, nu);

         // keys of bob
         const Botan::ECDH_PrivateKey other_private_key(Test::rng(), domain, x);
         const Botan::PointGFp other_public_key_point(curve, hx, hy);
         const Botan::ECDH_PublicKey other_public_key(domain, other_public_key_point);

         // (ephemeral) keys of alice
         const Botan::ECDH_PrivateKey eph_private_key(Test::rng(), domain, r);
         const Botan::PointGFp eph_public_key_point = eph_private_key.public_point();
         const std::vector<byte> eph_public_key_bin = Botan::unlock(
															Botan::EC2OSP(eph_public_key_point, compression_type));
         result.test_eq("encoded (ephemeral) public key", eph_public_key_bin, c0);

         // test secret derivation: ISO 18033 test vectors use KDF1 from ISO 18033
         // no cofactor-/oldcofactor-/singlehash-/check-mode and 128 byte secret length
         Botan::ECIES_KA_Params ka_params(eph_private_key.domain(), "KDF1-18033(SHA-1)", 128, compression_type, 
															Flags::NONE);
         const Botan::ECIES_KA_Operation ka(eph_private_key, ka_params, true);
         const Botan::SymmetricKey secret_key = ka.derive_secret(eph_public_key_bin, other_public_key_point);
         result.test_eq("derived secret key", secret_key.bits_of(), k);

         // test encryption / decryption
         for(int i_cofactor_mode = 0; i_cofactor_mode < 2; ++i_cofactor_mode)
            {
            for(int i_single_hash_mode = 0; i_single_hash_mode < 2; ++i_single_hash_mode)
               {
               for(int i_old_cofactor_mode = 0; i_old_cofactor_mode < 2; ++i_old_cofactor_mode)
                  {
                  for(int i_check_mode = 0; i_check_mode < 2; ++i_check_mode)
                     {
                     for(int i_compression_type = 0; i_compression_type < 3; ++i_compression_type)
                        {
                        const bool cofactor_mode = i_cofactor_mode != 0;
                        const bool single_hash_mode = i_single_hash_mode != 0;
                        const bool old_cofactor_mode = i_old_cofactor_mode != 0;
                        const bool check_mode = i_check_mode != 0;
                        const Botan::PointGFp::Compression_Type compression_type = 
							static_cast<Botan::PointGFp::Compression_Type>(i_compression_type);

                        Flags flags = ecies_flags(cofactor_mode, old_cofactor_mode, check_mode, single_hash_mode);

                        if(cofactor_mode + check_mode + old_cofactor_mode > 1)
                           {
                           result.test_throws("throw on invalid ECIES_Flags", [&]
                              {
                              Botan::ECIES_System_Params(eph_private_key.domain(), "KDF2(SHA-1)", "AES-256/CBC", 
															32, "HMAC(SHA-1)", 20, compression_type, flags);
                              });
                           continue;
                           }

                        Botan::ECIES_System_Params ecies_params(eph_private_key.domain(), "KDF2(SHA-1)", "AES-256/CBC",
															32, "HMAC(SHA-1)", 20, compression_type, flags);
                        check_encrypt_decrypt(result, eph_private_key, other_private_key, ecies_params, 16);
                        }
                     }
                  }
               }
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("ecies-iso", ECIES_ISO_Tests);


class ECIES_Tests : public Text_Based_Test
   {
   public:
      ECIES_Tests() : Text_Based_Test(
            "pubkey/ecies.vec",
         { "Curve", "PrivateKey", "OtherPrivateKey", "Kdf", "Dem", "DemKeyLen", "Iv", "Mac", "MacKeyLen", "Format",
				"CofactorMode", "OldCofactorMode", "CheckMode", "SingleHashMode", "Label", "Plaintext", "Ciphertext" })
         {
         }

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("ECIES");

         const std::string curve = get_req_str(vars, "Curve");
         const Botan::BigInt private_key_value = get_req_bn(vars, "PrivateKey");
         const Botan::BigInt other_private_key_value = get_req_bn(vars, "OtherPrivateKey");
         const std::string kdf = get_req_str(vars, "Kdf");
         const std::string dem = get_req_str(vars, "Dem");
         const size_t dem_key_len = get_req_sz(vars, "DemKeyLen");
         const std::vector<byte> iv = get_req_bin(vars, "Iv");
         const std::string mac = get_req_str(vars, "Mac");
         const size_t mac_key_len = get_req_sz(vars, "MacKeyLen");
         const Botan::PointGFp::Compression_Type compression_type = get_compression_type(get_req_str(vars, "Format"));
         const bool cofactor_mode = get_req_sz(vars, "CofactorMode") != 0;
         const bool old_cofactor_mode = get_req_sz(vars, "OldCofactorMode") != 0;
         const bool check_mode = get_req_sz(vars, "CheckMode") != 0;
         const bool single_hash_mode = get_req_sz(vars, "SingleHashMode") != 0;
         const std::string label = get_req_str(vars, "Label");
         const std::vector<byte> plaintext = get_req_bin(vars, "Plaintext");
         const std::vector<byte> ciphertext = get_req_bin(vars, "Ciphertext");

         const Flags flags = ecies_flags(cofactor_mode, old_cofactor_mode, check_mode, single_hash_mode);
         const Botan::EC_Group domain(curve);
         const Botan::ECDH_PrivateKey private_key(Test::rng(), domain, private_key_value);
         const Botan::ECDH_PrivateKey other_private_key(Test::rng(), domain, other_private_key_value);

         const Botan::ECIES_System_Params ecies_params(private_key.domain(), kdf, dem, dem_key_len, mac, mac_key_len,
               compression_type, flags);
         check_encrypt_decrypt(result, private_key, other_private_key, ecies_params, iv, label, plaintext, ciphertext);

         return result;
         }

   };

BOTAN_REGISTER_TEST("ecies", ECIES_Tests);

#endif

}

}
