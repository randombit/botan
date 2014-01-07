/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include "tests.h"
#include "test_rng.h"
#include "test_pubkey.h"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <memory>

#include <botan/botan.h>
#include <botan/oids.h>

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
  #include <botan/x509_key.h>
  #include <botan/pkcs8.h>
  #include <botan/pubkey.h>
#endif

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include <botan/dh.h>
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
  #include <botan/nr.h>
#endif

#if defined(BOTAN_HAS_RW)
  #include <botan/rw.h>
#endif

#if defined(BOTAN_HAS_ELGAMAL)
  #include <botan/elgamal.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_ECDH)
  #include <botan/ecdh.h>
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
  #include <botan/gost_3410.h>
#endif

#if defined(BOTAN_HAS_DLIES)
  #include <botan/dlies.h>
  #include <botan/kdf.h>
#endif

#include <botan/filters.h>
#include <botan/numthry.h>
using namespace Botan;

namespace {

void dump_data(const std::vector<byte>& out,
               const std::vector<byte>& expected)
   {
   Pipe pipe(new Hex_Encoder);

   pipe.process_msg(out);
   pipe.process_msg(expected);
   std::cout << "Got: " << pipe.read_all_as_string(0) << std::endl;
   std::cout << "Exp: " << pipe.read_all_as_string(1) << std::endl;
   }

size_t validate_save_and_load(const Private_Key* priv_key,
                              RandomNumberGenerator& rng)
   {
   std::string name = priv_key->algo_name();

   size_t fails = 0;
   std::string pub_pem = X509::PEM_encode(*priv_key);

   try
      {
      DataSource_Memory input_pub(pub_pem);
      std::auto_ptr<Public_Key> restored_pub(X509::load_key(input_pub));

      if(!restored_pub.get())
         {
         std::cout << "Could not recover " << name << " public key\n";
         ++fails;
         }
      else if(restored_pub->check_key(rng, true) == false)
         {
         std::cout << "Restored pubkey failed self tests " << name << "\n";
         ++fails;
         }
      }
   catch(std::exception& e)
      {
      std::cout << "Exception during load of " << name
                << " key: " << e.what() << "\n";
      std::cout << "PEM for pubkey was:\n" << pub_pem << "\n";
      ++fails;
      }

   std::string priv_pem = PKCS8::PEM_encode(*priv_key);

   try
      {
      DataSource_Memory input_priv(priv_pem);
      std::auto_ptr<Private_Key> restored_priv(
         PKCS8::load_key(input_priv, rng));

      if(!restored_priv.get())
         {
         std::cout << "Could not recover " << name << " privlic key\n";
         ++fails;
         }
      else if(restored_priv->check_key(rng, true) == false)
         {
         std::cout << "Restored privkey failed self tests " << name << "\n";
         ++fails;
         }
      }
   catch(std::exception& e)
      {
      std::cout << "Exception during load of " << name
                << " key: " << e.what() << "\n";
      std::cout << "PEM for privkey was:\n" << priv_pem << "\n";
      ++fails;
      }

   return fails;
   }

size_t validate_decryption(PK_Decryptor& d, const std::string& algo,
                           const std::vector<byte> ctext,
                           const std::vector<byte> ptext)
   {
   size_t fails = 0;

   std::vector<byte> decrypted = unlock(d.decrypt(ctext));

   if(decrypted != ptext)
      {
      std::cout << "FAILED (decrypt): " << algo << std::endl;
      dump_data(decrypted, ptext);
      ++fails;
      }

   return fails;
   }

}

size_t validate_encryption(PK_Encryptor& e, PK_Decryptor& d,
                           const std::string& algo, const std::string& input,
                           const std::string& random, const std::string& exp)
   {
   std::vector<byte> message = hex_decode(input);
   std::vector<byte> expected = hex_decode(exp);
   Fixed_Output_RNG rng(hex_decode(random));

   size_t fails = 0;

   std::vector<byte> out = e.encrypt(message, rng);
   if(out != expected)
      {
      std::cout << "FAILED (encrypt): " << algo << std::endl;
      dump_data(out, expected);
      ++fails;
      }

   fails += validate_decryption(d, algo, out, message);

   return fails;
   }

size_t validate_signature(PK_Verifier& v, PK_Signer& s, const std::string& algo,
                          const std::string& input,
                          RandomNumberGenerator& rng,
                          const std::string& exp)
   {
   std::vector<byte> message = hex_decode(input);
   std::vector<byte> expected = hex_decode(exp);
   std::vector<byte> sig = s.sign_message(message, rng);

   size_t fails = 0;

   if(sig != expected)
      {
      std::cout << "FAILED (sign): " << algo << std::endl;
      dump_data(sig, expected);
      ++fails;
      }

   if(!v.verify_message(message, sig))
      {
      std::cout << "FAILED (verify): " << algo << std::endl;
      ++fails;
      }

   /* This isn't a very thorough testing method, but it will hopefully
      catch any really horrible errors */
   sig[0]++;
   if(v.verify_message(message, sig))
      {
      std::cout << "FAILED (accepted bad sig): " << algo << std::endl;
      ++fails;
      }

   return fails;
   }

size_t validate_signature(PK_Verifier& v, PK_Signer& s, const std::string& algo,
                        const std::string& input,
                        const std::string& random,
                        const std::string& exp)
   {
   Fixed_Output_RNG rng(hex_decode(random));

   return validate_signature(v, s, algo, input, rng, exp);
   }

size_t validate_kas(PK_Key_Agreement& kas, const std::string& algo,
                    const std::vector<byte>& pubkey, const std::string& output,
                    size_t keylen)
   {
   std::vector<byte> expected = hex_decode(output);

   std::vector<byte> got = unlock(kas.derive_key(keylen, pubkey).bits_of());

   size_t fails = 0;

   if(got != expected)
      {
      std::cout << "FAILED: " << algo << std::endl;
      dump_data(got, expected);
      ++fails;
      }

   return fails;
   }

size_t test_pk_keygen()
   {
   AutoSeeded_RNG rng;

   size_t tests = 0;
   size_t fails = 0;

#define DL_KEY(TYPE, GROUP)                             \
   {                                                    \
   TYPE key(rng, DL_Group(GROUP));                      \
   key.check_key(rng, true);                            \
   ++tests;                                             \
   fails += validate_save_and_load(&key, rng);          \
   }

#define EC_KEY(TYPE, GROUP)                             \
   {                                                    \
   TYPE key(rng, EC_Group(OIDS::lookup(GROUP)));        \
   key.check_key(rng, true);                            \
   ++tests;                                             \
   fails += validate_save_and_load(&key, rng);          \
   }

#if defined(BOTAN_HAS_RSA)
      {
      RSA_PrivateKey rsa1024(rng, 1024);
      rsa1024.check_key(rng, true);
      ++tests;
      fails += validate_save_and_load(&rsa1024, rng);

      RSA_PrivateKey rsa2048(rng, 2048);
      rsa2048.check_key(rng, true);
      ++tests;
      fails += validate_save_and_load(&rsa2048, rng);
      }
#endif

#if defined(BOTAN_HAS_RW)
      {
      RW_PrivateKey rw1024(rng, 1024);
      rw1024.check_key(rng, true);
      ++tests;
      fails += validate_save_and_load(&rw1024, rng);
      }
#endif

#if defined(BOTAN_HAS_DSA)
   DL_KEY(DSA_PrivateKey, "dsa/jce/1024");
   DL_KEY(DSA_PrivateKey, "dsa/botan/2048");
   DL_KEY(DSA_PrivateKey, "dsa/botan/3072");
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   DL_KEY(DH_PrivateKey, "modp/ietf/1024");
   DL_KEY(DH_PrivateKey, "modp/ietf/2048");
   DL_KEY(DH_PrivateKey, "modp/ietf/4096");
   DL_KEY(DH_PrivateKey, "dsa/jce/1024");
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
   DL_KEY(NR_PrivateKey, "dsa/jce/1024");
   DL_KEY(NR_PrivateKey, "dsa/botan/2048");
   DL_KEY(NR_PrivateKey, "dsa/botan/3072");
#endif

#if defined(BOTAN_HAS_ELGAMAL)
   DL_KEY(ElGamal_PrivateKey, "modp/ietf/1024");
   DL_KEY(ElGamal_PrivateKey, "dsa/jce/1024");
   DL_KEY(ElGamal_PrivateKey, "dsa/botan/2048");
   DL_KEY(ElGamal_PrivateKey, "dsa/botan/3072");
#endif

#if defined(BOTAN_HAS_ECDSA)
   EC_KEY(ECDSA_PrivateKey, "secp112r1");
   EC_KEY(ECDSA_PrivateKey, "secp128r1");
   EC_KEY(ECDSA_PrivateKey, "secp160r1");
   EC_KEY(ECDSA_PrivateKey, "secp192r1");
   EC_KEY(ECDSA_PrivateKey, "secp224r1");
   EC_KEY(ECDSA_PrivateKey, "secp256r1");
   EC_KEY(ECDSA_PrivateKey, "secp384r1");
   EC_KEY(ECDSA_PrivateKey, "secp521r1");
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
   EC_KEY(GOST_3410_PrivateKey, "gost_256A");
   EC_KEY(GOST_3410_PrivateKey, "secp112r1");
   EC_KEY(GOST_3410_PrivateKey, "secp128r1");
   EC_KEY(GOST_3410_PrivateKey, "secp160r1");
   EC_KEY(GOST_3410_PrivateKey, "secp192r1");
   EC_KEY(GOST_3410_PrivateKey, "secp224r1");
   EC_KEY(GOST_3410_PrivateKey, "secp256r1");
   EC_KEY(GOST_3410_PrivateKey, "secp384r1");
   EC_KEY(GOST_3410_PrivateKey, "secp521r1");
#endif

   test_report("Keygen", tests, fails);

   return fails;
   }
