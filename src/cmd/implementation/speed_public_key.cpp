/*
* (C) 2009-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "../apps.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)

#include "speed.h"
#include "timer.h"

#include <map>
#include <sstream>
#include <botan/mem_ops.h>
#include <botan/parsing.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/x509_key.h>

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include <botan/dh.h>
#endif

#if defined(BOTAN_HAS_CURVE_25519)
  #include <botan/curve25519.h>
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

#if defined(BOTAN_HAS_DLIES) && defined(BOTAN_HAS_KDF2)
  #include <botan/dlies.h>
  #include <botan/kdf2.h>
  #include <botan/hmac.h>
  #include <botan/sha160.h>
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

#if defined(BOTAN_HAS_MCELIECE)
  #include <botan/mceliece.h>
  #include <botan/mce_kem.h>
#endif

using namespace Botan;

#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <set>

namespace {

const char* ec_domains[] = {
   //   "secp160r2",
   //   "secp192r1",
   //   "secp224r1",
   "secp256r1",
   "secp384r1",
   "secp521r1",
   //"brainpool256r1",
   //"brainpool384r1",
   //"brainpool512r1",
   nullptr
};

class Benchmark_Report
   {
   public:
      void report(const std::string& name, Timer timer)
         {
         std::cout << name << " " << timer << std::endl;
         data[name].insert(timer);
         }

   private:
      std::map<std::string, std::set<Timer> > data;
   };

void benchmark_enc_dec(PK_Encryptor& enc, PK_Decryptor& dec,
                       Timer& enc_timer, Timer& dec_timer,
                       RandomNumberGenerator& rng,
                       u32bit runs, double seconds)
   {
   std::vector<byte> plaintext, ciphertext;

   for(u32bit i = 0; i != runs; ++i)
      {
      if(enc_timer.seconds() < seconds || ciphertext.size() == 0)
         {
         plaintext.resize(enc.maximum_input_size());

         // Ensure for Raw, etc, it stays large
         if((i % 100) == 0)
            {
            rng.randomize(&plaintext[0], plaintext.size());
            plaintext[0] |= 0x80;
            }

         enc_timer.start();
         ciphertext = enc.encrypt(plaintext, rng);
         enc_timer.stop();
         }

      if(dec_timer.seconds() < seconds)
         {
         dec_timer.start();
         std::vector<byte> plaintext_out = unlock(dec.decrypt(ciphertext));
         dec_timer.stop();

         if(plaintext_out != plaintext)
            { // has never happened...
            std::cerr << "Contents mismatched on decryption during benchmark!" << std::endl;
            }
         }
      }
   }

void benchmark_sig_ver(PK_Verifier& ver, PK_Signer& sig,
                       Timer& verify_timer, Timer& sig_timer,
                       RandomNumberGenerator& rng,
                       u32bit runs, double seconds)
   {
   std::vector<byte> message, signature, sig_random;

   for(u32bit i = 0; i != runs; ++i)
      {
      if(sig_timer.seconds() < seconds || signature.size() == 0)
         {
         if((i % 100) == 0)
            {
            message.resize(48);
            rng.randomize(&message[0], message.size());
            }
         else
            message[0]++;

         sig_timer.start();
         signature = sig.sign_message(message, rng);
         sig_timer.stop();
         }

      if(verify_timer.seconds() < seconds)
         {
         verify_timer.start();
         const bool verified = ver.verify_message(message, signature);
         verify_timer.stop();

         if(!verified)
            std::cerr << "Signature verification failure" << std::endl;

         if((i % 100) == 0)
            {
            sig_random = unlock(rng.random_vec(signature.size()));

            verify_timer.start();
            const bool verified_bad = ver.verify_message(message, sig_random);
            verify_timer.stop();

            if(verified_bad)
               std::cerr << "Signature verification failure (bad sig OK)" << std::endl;
            }
         }
      }
   }

/*
  Between benchmark_rsa_rw + benchmark_dsa_nr:
     Type of the key
     Arguments to the constructor (A list of some arbitrary type?)
     Type of padding
*/

#if defined(BOTAN_HAS_RSA)
void benchmark_rsa(const std::string& provider,
                   RandomNumberGenerator& rng,
                   double seconds,
                   Benchmark_Report& report)
   {

   size_t keylens[] = { 1024, 2048, 4096, 6144, 0 };

   for(size_t i = 0; keylens[i]; ++i)
      {
      size_t keylen = keylens[i];

      //const std::string sig_padding = "PSSR(SHA-256)";
      //const std::string enc_padding = "OAEP(SHA-1)";
      const std::string sig_padding = "EMSA-PKCS1-v1_5(SHA-1)";
      const std::string enc_padding = "EME-PKCS1-v1_5";

      Timer keygen_timer("keygen");
      Timer verify_timer(sig_padding + " verify");
      Timer sig_timer(sig_padding + " signature");
      Timer enc_timer(enc_padding + " encrypt");
      Timer dec_timer(enc_padding + " decrypt");

      try
         {

#if 0
         // for profiling
         PKCS8_PrivateKey* pkcs8_key =
            PKCS8::load_key("rsa/" + to_string(keylen) + ".pem", rng);
         RSA_PrivateKey* key_ptr = dynamic_cast<RSA_PrivateKey*>(pkcs8_key);

         RSA_PrivateKey key = *key_ptr;
#else
         keygen_timer.start();
         RSA_PrivateKey key(rng, keylen);
         keygen_timer.stop();
#endif

         while(verify_timer.seconds() < seconds ||
               sig_timer.seconds() < seconds)
            {
            PK_Encryptor_EME enc(key, enc_padding, provider);
            PK_Decryptor_EME dec(key, enc_padding, provider);

            benchmark_enc_dec(enc, dec, enc_timer, dec_timer,
                              rng, 10000, seconds);

            PK_Signer sig(key, sig_padding, IEEE_1363, provider);
            PK_Verifier ver(key, sig_padding, IEEE_1363, provider);

            benchmark_sig_ver(ver, sig, verify_timer,
                              sig_timer, rng, 10000, seconds);
            }

         const std::string rsa_keylen = "RSA-" + std::to_string(keylen);

         report.report(rsa_keylen, keygen_timer);
         report.report(rsa_keylen, verify_timer);
         report.report(rsa_keylen, sig_timer);
         report.report(rsa_keylen, enc_timer);
         report.report(rsa_keylen, dec_timer);
         }
      catch(Stream_IO_Error)
         {
         }
      catch(Exception& e)
         {
         std::cout << e.what() << std::endl;
         }
      }

   }
#endif

#if defined(BOTAN_HAS_RW)
void benchmark_rw(RandomNumberGenerator& rng,
                  double seconds,
                  Benchmark_Report& report)
   {

   const u32bit keylens[] = { 1024, 2048, 4096, 6144, 0 };

   for(size_t j = 0; keylens[j]; j++)
      {
      u32bit keylen = keylens[j];

      std::string padding = "EMSA2(SHA-256)";

      Timer keygen_timer("keygen");
      Timer verify_timer(padding + " verify");
      Timer sig_timer(padding + " signature");

      while(verify_timer.seconds() < seconds ||
            sig_timer.seconds() < seconds)
         {
         keygen_timer.start();
         RW_PrivateKey key(rng, keylen);
         keygen_timer.stop();

         PK_Signer sig(key, padding);
         PK_Verifier ver(key, padding);

         benchmark_sig_ver(ver, sig, verify_timer, sig_timer,
                           rng, 10000, seconds);
         }

      const std::string nm = "RW-" + std::to_string(keylen);
      report.report(nm, keygen_timer);
      report.report(nm, verify_timer);
      report.report(nm, sig_timer);
      }
   }
#endif

#if defined(BOTAN_HAS_ECDSA)

void benchmark_ecdsa(const std::string& provider,
                     RandomNumberGenerator& rng,
                     double seconds,
                     Benchmark_Report& report)
   {
   for(size_t j = 0; ec_domains[j]; j++)
      {
      EC_Group params(ec_domains[j]);

      const size_t pbits = params.get_curve().get_p().bits();

      size_t hashbits = pbits;

      if(hashbits <= 192)
         hashbits = 160;
      if(hashbits == 521)
         hashbits = 512;

      const std::string padding = "EMSA1(SHA-" + std::to_string(hashbits) + ")";

      Timer keygen_timer("keygen");
      Timer verify_timer(padding + " verify");
      Timer sig_timer(padding + " signature");

      while(verify_timer.seconds() < seconds ||
            sig_timer.seconds() < seconds)
         {
         keygen_timer.start();
         ECDSA_PrivateKey key(rng, params);
         keygen_timer.stop();

         PK_Signer sig(key, padding, IEEE_1363, provider);
         PK_Verifier ver(key, padding, IEEE_1363, provider);

         benchmark_sig_ver(ver, sig, verify_timer,
                           sig_timer, rng, 1000, seconds);
         }

      const std::string nm = std::string("ECDSA ") + ec_domains[j];

      report.report(nm, keygen_timer);
      report.report(nm, verify_timer);
      report.report(nm, sig_timer);
      }
   }

#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)

void benchmark_gost_3410(RandomNumberGenerator& rng,
                         double seconds,
                         Benchmark_Report& report)
   {
   for(size_t j = 0; ec_domains[j]; j++)
      {
      EC_Group params(ec_domains[j]);

      const size_t pbits = params.get_curve().get_p().bits();

      const std::string padding = "EMSA1(GOST-34.11)";

      Timer keygen_timer("keygen");
      Timer verify_timer(padding + " verify");
      Timer sig_timer(padding + " signature");

      while(verify_timer.seconds() < seconds ||
            sig_timer.seconds() < seconds)
         {
         keygen_timer.start();
         GOST_3410_PrivateKey key(rng, params);
         keygen_timer.stop();

         PK_Signer sig(key, padding, IEEE_1363);
         PK_Verifier ver(key, padding);

         benchmark_sig_ver(ver, sig, verify_timer,
                           sig_timer, rng, 1000, seconds);
         }

      const std::string nm = "GOST-34.10-" + std::to_string(pbits);

      report.report(nm, keygen_timer);
      report.report(nm, verify_timer);
      report.report(nm, sig_timer);
      }
   }

#endif

#if defined(BOTAN_HAS_ECDH)

void benchmark_ecdh(RandomNumberGenerator& rng,
                    double seconds,
                    Benchmark_Report& report)
   {
   for(size_t j = 0; ec_domains[j]; j++)
      {
      EC_Group params(ec_domains[j]);

      size_t pbits = params.get_curve().get_p().bits();

      Timer keygen_timer("keygen");
      Timer kex_timer("key exchange");

      while(kex_timer.seconds() < seconds)
         {
         keygen_timer.start();
         ECDH_PrivateKey ecdh1(rng, params);
         keygen_timer.stop();

         keygen_timer.start();
         ECDH_PrivateKey ecdh2(rng, params);
         keygen_timer.stop();

         PK_Key_Agreement ka1(ecdh1, "KDF2(SHA-1)");
         PK_Key_Agreement ka2(ecdh2, "KDF2(SHA-1)");

         SymmetricKey secret1, secret2;

         for(size_t i = 0; i != 1000; ++i)
            {
            if(kex_timer.seconds() > seconds)
               break;

            kex_timer.start();
            secret1 = ka1.derive_key(32, ecdh2.public_value());
            kex_timer.stop();

            kex_timer.start();
            secret2 = ka2.derive_key(32, ecdh1.public_value());
            kex_timer.stop();

            if(secret1 != secret2)
               std::cerr << "ECDH secrets did not match" << std::endl;
            }
         }

      const std::string nm = "ECDH-" + std::to_string(pbits);
      report.report(nm, keygen_timer);
      report.report(nm, kex_timer);
      }
   }

#endif

template<typename PRIV_KEY_TYPE>
void benchmark_dsa_nr(RandomNumberGenerator& rng,
                      double seconds,
                      Benchmark_Report& report)
   {
#if defined(BOTAN_HAS_NYBERG_RUEPPEL) || defined(BOTAN_HAS_DSA)
   const char* domains[] = { "dsa/jce/1024",
                             "dsa/botan/2048",
                             "dsa/botan/3072",
                             nullptr };

   std::string algo_name;

   for(size_t j = 0; domains[j]; j++)
      {
      size_t pbits = to_u32bit(split_on(domains[j], '/')[2]);
      size_t qbits = (pbits <= 1024) ? 160 : 256;

      const std::string padding = "EMSA1(SHA-" + std::to_string(qbits) + ")";

      Timer keygen_timer("keygen");
      Timer verify_timer(padding + " verify");
      Timer sig_timer(padding + " signature");

      while(verify_timer.seconds() < seconds ||
            sig_timer.seconds() < seconds)
         {
         DL_Group group(domains[j]);

         keygen_timer.start();
         PRIV_KEY_TYPE key(rng, group);
         algo_name = key.algo_name();
         keygen_timer.stop();

         PK_Signer sig(key, padding, IEEE_1363);
         PK_Verifier ver(key, padding);

         benchmark_sig_ver(ver, sig, verify_timer,
                           sig_timer, rng, 1000, seconds);
         }

      const std::string nm = algo_name + "-" + std::to_string(pbits);
      report.report(nm, keygen_timer);
      report.report(nm, verify_timer);
      report.report(nm, sig_timer);
      }
#endif
   }

#if defined(BOTAN_HAS_CURVE_25519)
void benchmark_curve25519(RandomNumberGenerator& rng,
                          double seconds,
                          Benchmark_Report& report)
   {
   Timer keygen_timer("keygen");
   Timer kex_timer("key exchange");

   while(kex_timer.seconds() < seconds)
      {
      keygen_timer.start();
      Curve25519_PrivateKey key1(rng);
      keygen_timer.stop();

      keygen_timer.start();
      Curve25519_PrivateKey key2(rng);
      keygen_timer.stop();

      PK_Key_Agreement ka1(key1, "KDF2(SHA-256)");
      PK_Key_Agreement ka2(key2, "KDF2(SHA-256)");

      SymmetricKey secret1, secret2;

      for(size_t i = 0; i != 1000; ++i)
         {
         if(kex_timer.seconds() > seconds)
            break;

         kex_timer.start();
         secret1 = ka1.derive_key(32, key2.public_value());
         kex_timer.stop();

         kex_timer.start();
         secret2 = ka2.derive_key(32, key1.public_value());
         kex_timer.stop();

         if(secret1 != secret2)
            std::cerr << "Curve25519 secrets did not match" << std::endl;
         }
      }

   const std::string nm = "Curve25519";
   report.report(nm, keygen_timer);
   report.report(nm, kex_timer);
   }
#endif

#ifdef BOTAN_HAS_DIFFIE_HELLMAN
void benchmark_dh(RandomNumberGenerator& rng,
                  double seconds,
                  Benchmark_Report& report)
   {
   const char* domains[] = { "modp/ietf/1024",
                             "modp/ietf/2048",
                             "modp/ietf/3072",
                             "modp/ietf/4096",
                             "modp/ietf/6144",
                             "modp/ietf/8192",
                             nullptr };

   for(size_t j = 0; domains[j]; j++)
      {
      Timer keygen_timer("keygen");
      Timer kex_timer("key exchange");

      while(kex_timer.seconds() < seconds)
         {
         DL_Group group(domains[j]);

         keygen_timer.start();
         DH_PrivateKey dh1(rng, group);
         keygen_timer.stop();

         keygen_timer.start();
         DH_PrivateKey dh2(rng, group);
         keygen_timer.stop();

         PK_Key_Agreement ka1(dh1, "KDF2(SHA-1)");
         PK_Key_Agreement ka2(dh2, "KDF2(SHA-1)");

         SymmetricKey secret1, secret2;

         for(size_t i = 0; i != 1000; ++i)
            {
            if(kex_timer.seconds() > seconds)
               break;

            kex_timer.start();
            secret1 = ka1.derive_key(32, dh2.public_value());
            kex_timer.stop();

            kex_timer.start();
            secret2 = ka2.derive_key(32, dh1.public_value());
            kex_timer.stop();

            if(secret1 != secret2)
               std::cerr << "DH secrets did not match" << std::endl;
            }
         }

      const std::string nm = "DH-" + split_on(domains[j], '/')[2];
      report.report(nm, keygen_timer);
      report.report(nm, kex_timer);
      }
   }
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN) && defined(BOTAN_HAS_DLIES) && defined(BOTAN_HAS_KDF2)
void benchmark_dlies(RandomNumberGenerator& rng,
                     double seconds,
                     Benchmark_Report& report)
   {
   const char* domains[] = { "modp/ietf/768",
                             "modp/ietf/1024",
                             "modp/ietf/2048",
                             "modp/ietf/3072",
                             "modp/ietf/4096",
                             "modp/ietf/6144",
                             "modp/ietf/8192",
                             nullptr };

   for(size_t j = 0; domains[j]; j++)
      {
      Timer keygen_timer("keygen");
      Timer kex_timer("key exchange");

      Timer enc_timer("encrypt");
      Timer dec_timer("decrypt");

      while(enc_timer.seconds() < seconds || dec_timer.seconds() < seconds)
         {
         DL_Group group(domains[j]);

         keygen_timer.start();
         DH_PrivateKey dh1_priv(rng, group);
         keygen_timer.stop();

         keygen_timer.start();
         DH_PrivateKey dh2_priv(rng, group);
         keygen_timer.stop();

         DH_PublicKey dh2_pub(dh2_priv);

         DLIES_Encryptor dlies_enc(dh1_priv,
                                   new KDF2(new SHA_160),
                                   new HMAC(new SHA_160));

         dlies_enc.set_other_key(dh2_pub.public_value());

         DLIES_Decryptor dlies_dec(dh2_priv,
                                   new KDF2(new SHA_160),
                                   new HMAC(new SHA_160));

         benchmark_enc_dec(dlies_enc, dlies_dec,
                           enc_timer, dec_timer, rng,
                           1000, seconds);
         }

      const std::string nm = "DLIES-" + split_on(domains[j], '/')[2];
      report.report(nm, keygen_timer);
      report.report(nm, enc_timer);
      report.report(nm, dec_timer);
      }
   }
#endif

#ifdef BOTAN_HAS_ELGAMAL
void benchmark_elg(RandomNumberGenerator& rng,
                   double seconds,
                   Benchmark_Report& report)
   {
   const char* domains[] = { "modp/ietf/768",
                             "modp/ietf/1024",
                             "modp/ietf/2048",
                             "modp/ietf/3072",
                             "modp/ietf/4096",
                             "modp/ietf/6144",
                             "modp/ietf/8192",
                             nullptr };

   const std::string algo_name = "ElGamal";

   for(size_t j = 0; domains[j]; j++)
      {
      size_t pbits = to_u32bit(split_on(domains[j], '/')[2]);

      const std::string padding = "EME1(SHA-1)";

      Timer keygen_timer("keygen");
      Timer enc_timer(padding + " encrypt");
      Timer dec_timer(padding + " decrypt");

      while(enc_timer.seconds() < seconds ||
            dec_timer.seconds() < seconds)
         {
         DL_Group group(domains[j]);

         keygen_timer.start();
         ElGamal_PrivateKey key(rng, group);
         keygen_timer.stop();

         PK_Decryptor_EME dec(key, padding);
         PK_Encryptor_EME enc(key, padding);

         benchmark_enc_dec(enc, dec, enc_timer, dec_timer,
                           rng, 1000, seconds);
         }

      const std::string nm = algo_name + "-" + std::to_string(pbits);
      report.report(nm, keygen_timer);
      report.report(nm, enc_timer);
      report.report(nm, dec_timer);
      }
   }
#endif

#if defined(BOTAN_HAS_MCELIECE)
void benchmark_mce(RandomNumberGenerator& rng,
                   double seconds,
                   Benchmark_Report& report)
   {
   const std::vector<std::pair<size_t, size_t>> params = {
      { 1632, 33 },
      { 2480, 45 },
      { 2960, 57 },
      { 3408, 67 },
      { 4264, 95 },
      { 6624, 115 }
   };

   const std::string algo_name = "McEliece";

   for(auto& param : params)
      {
      Timer keygen_timer("keygen");
      Timer enc_timer("encrypt");
      Timer dec_timer("decrypt");

      keygen_timer.start();
      McEliece_PrivateKey priv_key(rng, param.first, param.second);
      McEliece_PublicKey pub_key(priv_key.x509_subject_public_key());
      keygen_timer.stop();

      McEliece_KEM_Encryptor enc_kem(pub_key);
      McEliece_KEM_Decryptor dec_kem(priv_key);

      while(enc_timer.seconds() < seconds ||
            dec_timer.seconds() < seconds)
         {
         enc_timer.start();
         auto enc_pair = enc_kem.encrypt(rng);
         enc_timer.stop();

         dec_timer.start();
         auto dec_key = dec_kem.decrypt_vec(enc_pair.first);
         dec_timer.stop();

         BOTAN_ASSERT_EQUAL(enc_pair.second, dec_key, "KEM result matches");
         }

      const std::string nm = algo_name + "-" +
                             std::to_string(param.first) + "," +
                             std::to_string(param.second);

      std::ostringstream keysize_report;
      keysize_report << "(work factor " << pub_key.estimated_strength() << ", "
                     << "pub bytes " << pub_key.x509_subject_public_key().size() << " "
                     << "priv bytes " << priv_key.pkcs8_private_key().size() << ")";

      report.report(nm + " " + keysize_report.str(), keygen_timer);
      report.report(nm, enc_timer);
      report.report(nm, dec_timer);
      }
   }
#endif

}

void benchmark_public_key(RandomNumberGenerator& rng,
                          const std::string& algo,
                          const std::string& provider,
                          double seconds)
   {
   /*
     There is some strangeness going on here. It looks like algorithms
     at the end take some kind of penalty. For example, running the RW tests
     first got a result of:
         RW-1024: 148.14 ms / private operation
     but running them last output:
         RW-1024: 363.54 ms / private operation

     I think it's from memory fragmentation in the allocators, but I'm
     not really sure. Need to investigate.

     Until then, I've basically ordered the tests in order of most important
     algorithms (RSA, DSA) to least important (NR, RW).

     This strange behaviour does not seem to occur with DH (?)

     To get more accurate runs, use --bench-algo (RSA|DSA|DH|ELG|NR); in this
     case the distortion is less than 5%, which is good enough.

     We do random keys with the DL schemes, since it's so easy and fast to
     generate keys for them. For RSA and RW, we load the keys from a file.  The
     RSA keys are stored in a PKCS #8 structure, while RW is stored in a more
     ad-hoc format (the RW algorithm has no assigned OID that I know of, so
     there is no way to encode a RW key into a PKCS #8 structure).
   */

   Benchmark_Report report;

#if defined(BOTAN_HAS_RSA)
   if(algo == "All" || algo == "RSA")
      benchmark_rsa(provider, rng, seconds, report);
#endif

#if defined(BOTAN_HAS_DSA)
   if(algo == "All" || algo == "DSA")
      benchmark_dsa_nr<DSA_PrivateKey>(rng, seconds, report);
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(algo == "All" || algo == "ECDSA")
      benchmark_ecdsa(provider, rng, seconds, report);
#endif

#if defined(BOTAN_HAS_ECDH)
   if(algo == "All" || algo == "ECDH")
      benchmark_ecdh(rng, seconds, report);
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
   if(algo == "All" || algo == "GOST-34.10")
      benchmark_gost_3410(rng, seconds, report);
#endif

#if defined(BOTAN_HAS_CURVE_25519)
   if(algo == "All" || algo == "Curve25519")
      benchmark_curve25519(rng, seconds, report);
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(algo == "All" || algo == "DH")
      benchmark_dh(rng, seconds, report);
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN) && defined(BOTAN_HAS_DLIES) && defined(BOTAN_HAS_KDF2)
   if(algo == "All" || algo == "DLIES")
      benchmark_dlies(rng, seconds, report);
#endif

#if defined(BOTAN_HAS_ELGAMAL)
   if(algo == "All" || algo == "ELG" || algo == "ElGamal")
      benchmark_elg(rng, seconds, report);
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
   if(algo == "All" || algo == "NR")
      benchmark_dsa_nr<NR_PrivateKey>(rng, seconds, report);
#endif

#if defined(BOTAN_HAS_RW)
   if(algo == "All" || algo == "RW")
      benchmark_rw(rng, seconds, report);
#endif

#if defined(BOTAN_HAS_MCELIECE)
   if(algo == "All" || algo == "McEliece")
      benchmark_mce(rng, seconds, report);
#endif
   }
#endif // BOTAN_HAS_PUBLIC_KEY_CRYPTO
