#include <botan/pkcs8.h>
#include <botan/mem_ops.h>
#include <botan/look_pk.h>
#include <botan/libstate.h>
#include <botan/parsing.h>

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

#if defined(BOTAN_HAS_DLIES)
  #include <botan/dlies.h>
  #include <botan/kdf2.h>
  #include <botan/hmac.h>
  #include <botan/sha160.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_ECKAEG)
  #include <botan/eckaeg.h>
#endif

using namespace Botan;

#include "common.h"
#include "timer.h"
#include "bench.h"

#include <iostream>
#include <fstream>
#include <string>
#include <memory>

namespace {

void benchmark_enc_dec(PK_Encryptor& enc, PK_Decryptor& dec,
                       Timer& enc_timer, Timer& dec_timer,
                       RandomNumberGenerator& rng,
                       u32bit runs, double seconds)
   {
   SecureVector<byte> plaintext, ciphertext;

   for(u32bit i = 0; i != runs; ++i)
      {
      if(enc_timer.seconds() < seconds || ciphertext.size() == 0)
         {
         plaintext.create(enc.maximum_input_size());

         // Ensure for Raw, etc, it stays large
         if((i % 100) == 0)
            {
            rng.randomize(plaintext.begin(), plaintext.size());
            plaintext[0] |= 0x80;
            }

         enc_timer.start();
         ciphertext = enc.encrypt(plaintext, rng);
         enc_timer.stop();
         }

      if(dec_timer.seconds() < seconds)
         {
         dec_timer.start();
         SecureVector<byte> plaintext_out = dec.decrypt(ciphertext);
         dec_timer.stop();

         if(plaintext_out != plaintext)
            { // has never happened...
            std::cerr << "Contents mismatched on decryption during benchmark!\n";
            }
         }
      }
   }

void benchmark_sig_ver(PK_Verifier& ver, PK_Signer& sig,
                       Timer& verify_timer, Timer& sig_timer,
                       RandomNumberGenerator& rng,
                       u32bit runs, double seconds)
   {
   SecureVector<byte> message, signature, sig_random;

   for(u32bit i = 0; i != runs; ++i)
      {
      if(sig_timer.seconds() < seconds || signature.size() == 0)
         {
         if((i % 100) == 0)
            {
            message.create(48);
            rng.randomize(message.begin(), message.size());
            }

         sig_timer.start();
         signature = sig.sign_message(message, rng);
         sig_timer.stop();
         }

      if(verify_timer.seconds() < seconds)
         {
         verify_timer.start();
         bool verified = ver.verify_message(message, signature);
         verify_timer.stop();

         if(!verified)
            std::cerr << "Signature verification failure\n";

         if((i % 100) == 0)
            {
            sig_random.create(signature.size());
            rng.randomize(sig_random, sig_random.size());

            verify_timer.start();
            bool verified2 = ver.verify_message(message, sig_random);
            verify_timer.stop();

            if(verified2)
               std::cerr << "Signature verification failure (bad sig OK)\n";
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
void benchmark_rsa(RandomNumberGenerator& rng,
                   double seconds,
                   Benchmark_Report& report)
   {

   size_t keylens[] = { 512, 1024, 2048, 4096, 6144, 8192, 0 };

   for(size_t i = 0; keylens[i]; ++i)
      {
      size_t keylen = keylens[i];

      //const std::string sig_padding = "EMSA4(SHA-1)";
      //const std::string enc_padding = "EME1(SHA-1)";
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
            std::auto_ptr<PK_Encryptor> enc(get_pk_encryptor(key, enc_padding));
            std::auto_ptr<PK_Decryptor> dec(get_pk_decryptor(key, enc_padding));
            benchmark_enc_dec(*enc, *dec, enc_timer, dec_timer, rng, 10000, seconds);

            std::auto_ptr<PK_Signer> sig(get_pk_signer(key, sig_padding));
            std::auto_ptr<PK_Verifier> ver(get_pk_verifier(key, sig_padding));
            benchmark_sig_ver(*ver, *sig, verify_timer,
                              sig_timer, rng, 10000, seconds);
            }

         const std::string rsa_keylen = "RSA-" + to_string(keylen);

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
         std::cout << e.what() << "\n";
         }
      }

   }
#endif

#if defined(BOTAN_HAS_RW)
void benchmark_rw(RandomNumberGenerator& rng,
                  double seconds,
                  Benchmark_Report& report)
   {

   const u32bit keylens[] = { 512, 1024, 2048, 4096, 6144, 8192, 0 };

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

         std::auto_ptr<PK_Signer> sig(get_pk_signer(key, padding));
         std::auto_ptr<PK_Verifier> ver(get_pk_verifier(key, padding));

         benchmark_sig_ver(*ver, *sig, verify_timer, sig_timer, rng, 10000, seconds);
         }

      const std::string nm = "RW-" + to_string(keylen);
      report.report(nm, keygen_timer);
      report.report(nm, verify_timer);
      report.report(nm, sig_timer);
      }
   }
#endif

#if defined(BOTAN_HAS_ECDSA)

void benchmark_ecdsa(RandomNumberGenerator& rng,
                     double seconds,
                     Benchmark_Report& report)
   {
   const char* domains[] = { "1.3.132.0.6", // secp112r1
                             "1.3.132.0.28", // secp128r1
                             "1.3.132.0.30", // secp160r2
                             "1.3.132.0.33", // secp224r1
                             "1.3.132.0.34", // secp384r1
                             "1.3.132.0.35", // secp512r1
                             NULL };

   for(size_t j = 0; domains[j]; j++)
      {
      EC_Domain_Params params = get_EC_Dom_Pars_by_oid(domains[j]);

      u32bit pbits = params.get_curve().get_p().bits();

      u32bit hashbits = pbits;

      if(hashbits < 160)
         hashbits = 160;
      if(hashbits == 521)
         hashbits = 512;

      const std::string padding = "EMSA1(SHA-" + to_string(hashbits) + ")";

      Timer keygen_timer("keygen");
      Timer verify_timer(padding + " verify");
      Timer sig_timer(padding + " signature");

      while(verify_timer.seconds() < seconds ||
            sig_timer.seconds() < seconds)
         {
         keygen_timer.start();
         ECDSA_PrivateKey key(rng, params);
         keygen_timer.stop();

         std::auto_ptr<PK_Signer> sig(get_pk_signer(key, padding));
         std::auto_ptr<PK_Verifier> ver(get_pk_verifier(key, padding));

         benchmark_sig_ver(*ver, *sig, verify_timer,
                           sig_timer, rng, 1000, seconds);
         }

      const std::string nm = "ECDSA-" + to_string(pbits);

      report.report(nm, keygen_timer);
      report.report(nm, verify_timer);
      report.report(nm, sig_timer);
      }
   }

#endif

#if defined(BOTAN_HAS_ECKAEG)

void benchmark_eckaeg(RandomNumberGenerator& rng,
                      double seconds,
                      Benchmark_Report& report)
   {
   const char* domains[] = { "1.3.132.0.6", // secp112r1
                             "1.3.132.0.28", // secp128r1
                             "1.3.132.0.30", // secp160r2
                             "1.3.132.0.33", // secp224r1
                             "1.3.132.0.34", // secp384r1
                             "1.3.132.0.35", // secp512r1
                             NULL };

   for(size_t j = 0; domains[j]; j++)
      {
      EC_Domain_Params params = get_EC_Dom_Pars_by_oid(domains[j]);

      u32bit pbits = params.get_curve().get_p().bits();

      Timer keygen_timer("keygen");
      Timer kex_timer("key exchange");

      while(kex_timer.seconds() < seconds)
         {
         keygen_timer.start();
         ECKAEG_PrivateKey eckaeg1(rng, params);
         keygen_timer.stop();

         keygen_timer.start();
         ECKAEG_PrivateKey eckaeg2(rng, params);
         keygen_timer.stop();

         ECKAEG_PublicKey pub1(eckaeg1);
         ECKAEG_PublicKey pub2(eckaeg2);

         SecureVector<byte> secret1, secret2;

         for(u32bit i = 0; i != 1000; ++i)
            {
            if(kex_timer.seconds() > seconds)
               break;

            kex_timer.start();
            secret1 = eckaeg1.derive_key(pub2);
            kex_timer.stop();

            kex_timer.start();
            secret2 = eckaeg2.derive_key(pub1);
            kex_timer.stop();

            if(secret1 != secret2)
               std::cerr << "ECKAEG secrets did not match, bug in the library!?!\n";
            }
         }

      const std::string nm = "ECKAEG-" + to_string(pbits);
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
   const char* domains[] = { "dsa/jce/512",
                             "dsa/jce/768",
                             "dsa/jce/1024",
                             "dsa/botan/2048",
                             "dsa/botan/3072",
                             NULL };

   const std::string algo_name = PRIV_KEY_TYPE().algo_name();

   for(size_t j = 0; domains[j]; j++)
      {
      u32bit pbits = to_u32bit(split_on(domains[j], '/')[2]);
      u32bit qbits = (pbits <= 1024) ? 160 : 256;

      const std::string padding = "EMSA1(SHA-" + to_string(qbits) + ")";

      Timer keygen_timer("keygen");
      Timer verify_timer(padding + " verify");
      Timer sig_timer(padding + " signature");

      while(verify_timer.seconds() < seconds ||
            sig_timer.seconds() < seconds)
         {
         DL_Group group(domains[j]);

         keygen_timer.start();
         PRIV_KEY_TYPE key(rng, group);
         keygen_timer.stop();

         std::auto_ptr<PK_Signer> sig(get_pk_signer(key, padding));
         std::auto_ptr<PK_Verifier> ver(get_pk_verifier(key, padding));

         benchmark_sig_ver(*ver, *sig, verify_timer,
                           sig_timer, rng, 1000, seconds);
         }

      const std::string nm = algo_name + "-" + to_string(pbits);
      report.report(nm, keygen_timer);
      report.report(nm, verify_timer);
      report.report(nm, sig_timer);
      }
#endif
   }

#ifdef BOTAN_HAS_DIFFIE_HELLMAN
void benchmark_dh(RandomNumberGenerator& rng,
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
                             NULL };

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

         DH_PublicKey pub1(dh1);
         DH_PublicKey pub2(dh2);

         SecureVector<byte> secret1, secret2;

         for(u32bit i = 0; i != 1000; ++i)
            {
            if(kex_timer.seconds() > seconds)
               break;

            kex_timer.start();
            secret1 = dh1.derive_key(pub2);
            kex_timer.stop();

            kex_timer.start();
            secret2 = dh2.derive_key(pub1);
            kex_timer.stop();

            if(secret1 != secret2)
               std::cerr << "DH secrets did not match, bug in the library!?!\n";
            }
         }

      const std::string nm = "DH-" + split_on(domains[j], '/')[2];
      report.report(nm, keygen_timer);
      report.report(nm, kex_timer);
      }
   }
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN) && defined(BOTAN_HAS_DLIES)
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
                             NULL };

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
                             NULL };

   const std::string algo_name = "ElGamal";

   for(size_t j = 0; domains[j]; j++)
      {
      u32bit pbits = to_u32bit(split_on(domains[j], '/')[2]);

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

         std::auto_ptr<PK_Decryptor> dec(get_pk_decryptor(key, padding));
         std::auto_ptr<PK_Encryptor> enc(get_pk_encryptor(key, padding));

         benchmark_enc_dec(*enc, *dec, enc_timer, dec_timer, rng, 1000, seconds);
         }

      const std::string nm = algo_name + "-" + to_string(pbits);
      report.report(nm, keygen_timer);
      report.report(nm, enc_timer);
      report.report(nm, dec_timer);
      }
   }
#endif

}

void bench_pk(RandomNumberGenerator& rng,
              const std::string& algo, bool, double seconds)
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

   global_state().set_option("pk/test/private_gen", "basic");

   Benchmark_Report report;

#if defined(BOTAN_HAS_RSA)
   if(algo == "All" || algo == "RSA")
      benchmark_rsa(rng, seconds, report);
#endif

#if defined(BOTAN_HAS_DSA)
   if(algo == "All" || algo == "DSA")
      benchmark_dsa_nr<DSA_PrivateKey>(rng, seconds, report);
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(algo == "All" || algo == "ECDSA")
      benchmark_ecdsa(rng, seconds, report);
#endif

#if defined(BOTAN_HAS_ECKAEG)
   if(algo == "All" || algo == "ECKAEG")
      benchmark_eckaeg(rng, seconds, report);
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(algo == "All" || algo == "DH")
      benchmark_dh(rng, seconds, report);
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN) && defined(BOTAN_HAS_DLIES)
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
   }
