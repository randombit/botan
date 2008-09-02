#include <botan/dsa.h>
#include <botan/rsa.h>
#include <botan/dh.h>
#include <botan/nr.h>
#include <botan/rw.h>
#include <botan/elgamal.h>
#include <botan/parsing.h>

#include <botan/pkcs8.h>
#include <botan/mem_ops.h>
#include <botan/look_pk.h>

using namespace Botan;

#include "common.h"
#include "timer.h"
#include "bench.h"

#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <map>
#include <set>

#define PRINT_MS_PER_OP 0 /* If 0, print ops / second */

class Benchmark_Report
   {
   public:
      void report(const std::string& name, Timer timer)
         {
         std::cout << name << " " << timer << "\n";
         data[name].insert(timer);
         }

   private:
      std::map<std::string, std::set<Timer> > data;
   };

void bench_kas(PK_Key_Agreement*, RandomNumberGenerator&,
               const std::string&, double, bool);

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
         plaintext.create(48);
         rng.randomize(plaintext.begin(), plaintext.size());
         plaintext[0] |= 0x80;

         enc_timer.start();
         ciphertext = enc.encrypt(plaintext, rng);
         enc_timer.stop();
         }

      if(dec_timer.seconds() < seconds)
         {
         dec_timer.start();
         SecureVector<byte> plaintext2 = dec.decrypt(ciphertext);
         dec_timer.stop();

         if(plaintext != plaintext2)
            std::cerr << "Contents mismatched on decryption in RSA benchmark!\n";
         }
      }
   }

void benchmark_sig_ver(PK_Verifier& ver, PK_Signer& sig,
                       Timer& verify_timer, Timer& sig_timer,
                       RandomNumberGenerator& rng,
                       u32bit runs, double seconds)
   {
   SecureVector<byte> message, signature;

   for(u32bit i = 0; i != runs; ++i)
      {
      if(sig_timer.seconds() < seconds || signature.size() == 0)
         {
         message.create(48);
         rng.randomize(message.begin(), message.size());

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
         }
      }
   }

template<typename PRIV_KEY_TYPE>
void benchmark_rsa_rw(RandomNumberGenerator& rng,
                      double seconds,
                      Benchmark_Report& report)
   {
   const u32bit keylens[] = { 512, 1024, 2048, 3072, 4096, 6144, 8192, 0 };

   const std::string algo_name = PRIV_KEY_TYPE().algo_name();

   for(size_t j = 0; keylens[j]; j++)
      {
      u32bit keylen = keylens[j];

      Timer keygen_timer("keygen");
      Timer verify_timer("verify");
      Timer sig_timer("signature");

      while(verify_timer.seconds() < seconds ||
            sig_timer.seconds() < seconds)
         {
         keygen_timer.start();
         PRIV_KEY_TYPE key(rng, keylen);
         keygen_timer.stop();

         std::string padding = "EMSA4(SHA-1)";

         std::auto_ptr<PK_Signer> sig(get_pk_signer(key, padding));
         std::auto_ptr<PK_Verifier> ver(get_pk_verifier(key, padding));

         benchmark_sig_ver(*ver, *sig, verify_timer, sig_timer, rng, 10000, seconds);
         }

      const std::string nm = algo_name + "-" + to_string(keylen);
      report.report(nm, keygen_timer);
      report.report(nm, verify_timer);
      report.report(nm, sig_timer);
      }
   }

template<typename PRIV_KEY_TYPE>
void benchmark_dsa_nr(RandomNumberGenerator& rng,
                      double seconds,
                      Benchmark_Report& report)
   {
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

      Timer keygen_timer("keygen");
      Timer verify_timer("verify");
      Timer sig_timer("signature");

      while(verify_timer.seconds() < seconds ||
            sig_timer.seconds() < seconds)
         {
         DL_Group group(domains[j]);

         keygen_timer.start();
         PRIV_KEY_TYPE key(rng, group);
         keygen_timer.stop();

         const std::string padding = "EMSA1(SHA-" + to_string(qbits) + ")";

         std::auto_ptr<PK_Signer> sig(get_pk_signer(key, padding));
         std::auto_ptr<PK_Verifier> ver(get_pk_verifier(key, padding));

         benchmark_sig_ver(*ver, *sig, verify_timer, sig_timer, rng, 100, seconds);
         }

      const std::string nm = algo_name + "-" + to_string(pbits);
      report.report(nm, keygen_timer);
      report.report(nm, verify_timer);
      report.report(nm, sig_timer);
      }
   }

void benchmark_elg(RandomNumberGenerator& rng,
                   double seconds,
                   Benchmark_Report& report)
   {
   const char* domains[] = { "modp/ietf/768",
                             "modp/ietf/1024",
                             "modp/ietf/2048",
                             "modp/ietf/3072",
                             "modp/ietf/4096",
                             NULL };

   const std::string algo_name = "ElGamal";

   for(size_t j = 0; domains[j]; j++)
      {
      u32bit pbits = to_u32bit(split_on(domains[j], '/')[2]);

      Timer keygen_timer("keygen");
      Timer enc_timer("encrypt");
      Timer dec_timer("decrypt");

      while(enc_timer.seconds() < seconds ||
            dec_timer.seconds() < seconds)
         {
         DL_Group group(domains[j]);

         keygen_timer.start();
         ElGamal_PrivateKey key(rng, group);
         keygen_timer.stop();

         const std::string padding = "Raw"; //"EME1(SHA-1)";

         std::auto_ptr<PK_Decryptor> dec(get_pk_decryptor(key, padding));
         std::auto_ptr<PK_Encryptor> enc(get_pk_encryptor(key, padding));

         benchmark_enc_dec(*enc, *dec, enc_timer, dec_timer, rng, 100, seconds);
         }

      const std::string nm = algo_name + "-" + to_string(pbits);
      report.report(nm, keygen_timer);
      report.report(nm, enc_timer);
      report.report(nm, dec_timer);
      }
   }

}

void bench_pk(RandomNumberGenerator& rng,
              const std::string& algo, bool html, double seconds)
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

   if(algo == "All" || algo == "RSA")
      {
      benchmark_rsa_rw<RSA_PrivateKey>(rng, seconds, report);
      }

   if(algo == "All" || algo == "DSA")
      {
      benchmark_dsa_nr<DSA_PrivateKey>(rng, seconds, report);
      }

   if(algo == "All" || algo == "DH")
      {
      const u32bit keylen[] = { 1024, 2048, 3072, 4096, 8192, 0 };

      for(size_t j = 0; keylen[j]; j++)
         {
         const std::string len_str = to_string(keylen[j]);

         DH_PrivateKey key(rng,
                           "modp/ietf/" + len_str);

         bench_kas(get_pk_kas(key, "Raw"), rng,
                   "DH-" + len_str, seconds, html);
         }
      }

   if(algo == "All" || algo == "ELG" || algo == "ElGamal")
      {

      /*
      const u32bit keylen[] = { 768, 1024, 1536, 2048, 3072, 4096, 0 };

      for(size_t j = 0; keylen[j]; j++)
         {
         const std::string len_str = to_string(keylen[j]);

         ElGamal_PrivateKey key(rng, "modp/ietf/" + len_str);

         bench_enc(get_pk_encryptor(key, "Raw"),
                   rng, "ELG-" + len_str, seconds, html);

         bench_dec(get_pk_encryptor(key, "Raw"),
                   get_pk_decryptor(key, "Raw"),
                   rng, "ELG-" + len_str, seconds, html);
         }
      */

      benchmark_elg(rng, seconds, report);

      }

   if(algo == "All" || algo == "NR")
      {
      benchmark_dsa_nr<NR_PrivateKey>(rng, seconds, report);
      }

   if(algo == "All" || algo == "RW")
      {
      benchmark_rsa_rw<RW_PrivateKey>(rng, seconds, report);
      }
   }

namespace {

void print_result(bool html, u32bit runs, u64bit clocks_used,
                  const std::string& algo_name, const std::string& op)
   {
   double seconds = static_cast<double>(clocks_used) / get_ticks();
   double mseconds_per_run = 1000 * (seconds / runs);
   double runs_per_sec = runs / seconds;

   if(html)
      {
      std::cout << "   <TR><TH>" << algo_name << " (" << op << ") <TH>";

      if(PRINT_MS_PER_OP)
         std::cout << mseconds_per_run;
      else
         std::cout << runs_per_sec;

      std::cout << std::endl;
      }
   else
      {
      std::cout << algo_name << ": ";

      std::cout.setf(std::ios::fixed, std::ios::floatfield);
      std::cout.precision(2);

      if(PRINT_MS_PER_OP)
         std::cout << mseconds_per_run << " ms / " << op << "\n";
      else
         std::cout << runs_per_sec << " ops / second (" << op << ")\n";
      }
   }

}

void bench_kas(PK_Key_Agreement* kas,
               RandomNumberGenerator& rng,
               const std::string& algo_name,
               double seconds, bool html)
   {
   /* 128 bits: should always be considered valid (what about ECC?) */
   static const u32bit REMOTE_KEY_SIZE = 16;
   byte key[REMOTE_KEY_SIZE];

   u32bit runs = 0;
   u64bit clocks_used = 0;

   const u64bit ticks = get_ticks();
   while(clocks_used < seconds * ticks)
      {
      runs++;
      rng.randomize(key, REMOTE_KEY_SIZE);

      u64bit start = get_clock();
      kas->derive_key(0, key, REMOTE_KEY_SIZE);
      clocks_used += get_clock() - start;
      }

   delete kas;

   print_result(html, runs, clocks_used, algo_name, "key agreement");
   }
