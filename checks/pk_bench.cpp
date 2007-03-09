#include <botan/dsa.h>
#include <botan/rsa.h>
#include <botan/dh.h>
#include <botan/pkcs8.h>
#include <botan/look_pk.h>
#include <botan/rng.h>

#if !defined(BOTAN_NO_NR)
  #include <botan/nr.h>
#endif

#if !defined(BOTAN_NO_RW)
  #include <botan/rw.h>
#endif

#if !defined(BOTAN_NO_ELG)
  #include <botan/elgamal.h>
#endif

using namespace Botan;

#include "common.h"

#include <iostream>
#include <fstream>
#include <string>

#define DEBUG 0

#define PRINT_MS_PER_OP 0 /* If 0, print ops / second */

RSA_PrivateKey* load_rsa_key(const std::string&);
#if !defined(BOTAN_NO_RW)
RW_PrivateKey  load_rw_key(const std::string&);
#endif

static BigInt to_bigint(const std::string& h)
   {
   return BigInt::decode((const byte*)h.data(),
                         h.length(), BigInt::Hexadecimal);
   }

void bench_enc(PK_Encryptor*, const std::string&, double, bool);
void bench_dec(PK_Encryptor*, PK_Decryptor*, const std::string&, double, bool);
void bench_sig(PK_Signer*, const std::string&, double, bool);
void bench_ver(PK_Signer*, PK_Verifier*, const std::string&, double, bool);
void bench_kas(PK_Key_Agreement*, const std::string&, double, bool);

void bench_rsa(RSA_PrivateKey& key, const std::string keybits,
               double seconds, bool html)
   {
   bench_enc(get_pk_encryptor(key, "Raw"),
             "RSA-" + keybits, seconds, html);
   bench_dec(get_pk_encryptor(key, "Raw"),
             get_pk_decryptor(key, "Raw"),
             "RSA-" + keybits, seconds, html);
   }

void bench_dsa(DSA_PrivateKey& key, const std::string keybits,
               double seconds, bool html)
   {
   bench_ver(get_pk_signer(key, "EMSA1(SHA-1)"),
             get_pk_verifier(key, "EMSA1(SHA-1)"),
             "DSA-" + keybits, seconds, html);
   bench_sig(get_pk_signer(key, "EMSA1(SHA-1)"),
             "DSA-" + keybits, seconds, html);
   }

void bench_dh(DH_PrivateKey& key, const std::string keybits,
              double seconds, bool html)
   {
   bench_kas(get_pk_kas(key, "Raw"),
             "DH-" + keybits, seconds, html);
   }

#if !defined(BOTAN_NO_RW)
void bench_rw(RW_PrivateKey& key, const std::string keybits,
              double seconds, bool html)
   {
   bench_ver(get_pk_signer(key, "EMSA2(SHA-1)"),
             get_pk_verifier(key, "EMSA2(SHA-1)"),
             "RW-" + keybits, seconds, html);
   bench_sig(get_pk_signer(key, "EMSA2(SHA-1)"),
             "RW-" + keybits, seconds, html);
   }
#endif

#if !defined(BOTAN_NO_NR)
void bench_nr(NR_PrivateKey& key, const std::string keybits,
              double seconds, bool html)
   {
   bench_ver(get_pk_signer(key, "EMSA1(SHA-1)"),
             get_pk_verifier(key, "EMSA1(SHA-1)"),
             "NR-" + keybits, seconds, html);
   bench_sig(get_pk_signer(key, "EMSA1(SHA-1)"),
             "NR-" + keybits, seconds, html);
   }
#endif

#if !defined(BOTAN_NO_ELG)
void bench_elg(ElGamal_PrivateKey& key, const std::string keybits,
               double seconds, bool html)
   {
   bench_enc(get_pk_encryptor(key, "Raw"),
             "ELG-" + keybits, seconds, html);
   bench_dec(get_pk_encryptor(key, "Raw"),
             get_pk_decryptor(key, "Raw"),
             "ELG-" + keybits, seconds, html);
   }
#endif

void bench_pk(const std::string& algo, bool html, double seconds)
   {
   /*
     There is some strangeness going on here. It looks like algorithms
     at the end take some kind of pentalty. For example, running the RW tests
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
   try {

   if(algo == "All" || algo == "RSA")
      {
      #define DO_RSA(NUM_STR, FILENAME)                \
         {                                             \
         RSA_PrivateKey* rsa = load_rsa_key(FILENAME); \
         bench_rsa(*rsa, NUM_STR, seconds, html);      \
         delete rsa;                                   \
         }

      DO_RSA("512", "checks/keys/rsa512.key")
      DO_RSA("1024", "checks/keys/rsa1024.key")
      DO_RSA("1536", "checks/keys/rsa1536.key")
      DO_RSA("2048", "checks/keys/rsa2048.key")
      DO_RSA("3072", "checks/keys/rsa3072.key")
      DO_RSA("4096", "checks/keys/rsa4096.key")
      #undef DO_RSA
      }
   if(algo == "All" || algo == "DSA")
      {
      #define DO_DSA(NUM_STR, GROUP)              \
         {                                        \
         DSA_PrivateKey dsa(GROUP);               \
         bench_dsa(dsa, NUM_STR, seconds, html);  \
         }

      DO_DSA("512",  DL_Group("dsa/jce/512"));
      DO_DSA("768",  DL_Group("dsa/jce/768"));
      DO_DSA("1024", DL_Group("dsa/jce/1024"));
      //DO_DSA("2048", DL_Group(DL_Group::DSA_Kosherizer, 2048, 256));
      //DO_DSA("3072", DL_Group(DL_Group::DSA_Kosherizer, 3072, 256));
      #undef DO_DSA
      }
   if(algo == "All" || algo == "DH")
      {
      #define DO_DH(NUM_STR, GROUP)             \
         {                                      \
         DH_PrivateKey dh(DL_Group(GROUP)); \
         bench_dh(dh, NUM_STR, seconds, html);  \
         }

      DO_DH("768", "modp/ietf/768");
      DO_DH("1024", "modp/ietf/1024");
      DO_DH("1536", "modp/ietf/1536");
      DO_DH("2048", "modp/ietf/2048");
      DO_DH("3072", "modp/ietf/3072");
      DO_DH("4096", "modp/ietf/4096");
      #undef DO_DH
      }
#if !defined(BOTAN_NO_ELG)
   if(algo == "All" || algo == "ELG" || algo == "ElGamal")
      {
      #define DO_ELG(NUM_STR, GROUP)                  \
         {                                            \
         ElGamal_PrivateKey elg(DL_Group(GROUP)); \
         bench_elg(elg, NUM_STR, seconds, html);      \
         }
      DO_ELG("768", "modp/ietf/768");
      DO_ELG("1024", "modp/ietf/1024");
      DO_ELG("1536", "modp/ietf/1536");
      DO_ELG("2048", "modp/ietf/2048");
      DO_ELG("3072", "modp/ietf/3072");
      DO_ELG("4096", "modp/ietf/4096");
      #undef DO_ELG
      }
#endif

#if !defined(BOTAN_NO_NR)
   if(algo == "All" || algo == "NR")
      {
      #define DO_NR(NUM_STR, GROUP)             \
         {                                      \
         NR_PrivateKey nr(DL_Group(GROUP)); \
         bench_nr(nr, NUM_STR, seconds, html);  \
         }

      DO_NR("512",  "dsa/jce/512");
      DO_NR("768",  "dsa/jce/768");
      DO_NR("1024", "dsa/jce/1024");
      #undef DO_NR
      }
#endif

#if !defined(BOTAN_NO_RW)
   if(algo == "All" || algo == "RW")
      {
      #define DO_RW(NUM_STR, FILENAME)             \
         {                                         \
         RW_PrivateKey rw = load_rw_key(FILENAME); \
         bench_rw(rw, NUM_STR, seconds, html);     \
         }

      DO_RW("512",  "checks/keys/rw512.key")
      DO_RW("1024", "checks/keys/rw1024.key")
      #undef DO_RW
      }
#endif
   }
   catch(Botan::Exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      return;
      }
   catch(std::exception& e)
      {
      std::cout << "Standard library exception caught: "
                << e.what() << std::endl;
      return;
      }
   catch(...)
      {
      std::cout << "Unknown exception caught." << std::endl;
      return;
      }

   }

void print_result(bool html, u32bit runs, u64bit clocks_used,
                  const std::string& algo_name, const std::string& op)
   {
   double seconds = (double)clocks_used / get_ticks();
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
         std::cout << mseconds_per_run << " ms / " << op << std::endl;
      else
         std::cout << runs_per_sec << " ops / second (" << op << ")" << std::endl;
      }
   }

void bench_enc(PK_Encryptor* enc, const std::string& algo_name,
               double seconds, bool html)
   {
   static const u32bit MSG_SIZE = 16;
   byte msg[MSG_SIZE];

   u32bit runs = 0;

   u64bit clocks_used = 0;

   const u64bit ticks = get_ticks();
   while(clocks_used < seconds * ticks)
      {
      runs++;
      Global_RNG::randomize(msg, MSG_SIZE);

      u64bit start = get_clock();
      enc->encrypt(msg, MSG_SIZE);
      clocks_used += get_clock() - start;
      }

   delete enc;

   print_result(html, runs, clocks_used, algo_name, "public operation");
   }

void bench_dec(PK_Encryptor* enc, PK_Decryptor* dec,
               const std::string& algo_name,
               double seconds, bool html)
   {
   static const u32bit MSG_SIZE = 16;
   byte msg[MSG_SIZE];
   Global_RNG::randomize(msg, MSG_SIZE);
   SecureVector<byte> output;

   u32bit runs = 0;
   u64bit clocks_used = 0;

   SecureVector<byte> encrypted_msg = enc->encrypt(msg, MSG_SIZE);

   const u64bit ticks = get_ticks();
   while(clocks_used < seconds * ticks)
      {
      runs++;

      Global_RNG::randomize(msg, MSG_SIZE);
      msg[0] |= 0x80; // make sure it works with "Raw" padding
      encrypted_msg = enc->encrypt(msg, MSG_SIZE);

      u64bit start = get_clock();
      output = dec->decrypt(encrypted_msg);
      clocks_used += get_clock() - start;

      if(output.size() != MSG_SIZE ||
         std::memcmp(msg, output, MSG_SIZE) != 0)
         {
         std::cout << hex_encode(msg, MSG_SIZE) << std::endl;
         std::cout << hex_encode(output, output.size()) << std::endl;
         throw Internal_Error("Decrypt check failed during benchmark");
         }
      }

   delete enc;
   delete dec;

   print_result(html, runs, clocks_used, algo_name, "private operation");
   }

void bench_sig(PK_Signer* sig, const std::string& algo_name,
               double seconds, bool html)
   {
   static const u32bit MSG_SIZE = 16;
   byte msg[MSG_SIZE];

   u32bit runs = 0;
   u64bit clocks_used = 0;

   const u64bit ticks = get_ticks();
   while(clocks_used < seconds * ticks)
      {
      runs++;
      Global_RNG::randomize(msg, MSG_SIZE);
      u64bit start = get_clock();
      sig->update(msg, MSG_SIZE);
      sig->signature();
      clocks_used += get_clock() - start;
      }

   delete sig;

   print_result(html, runs, clocks_used, algo_name, "private operation");
   }

void bench_ver(PK_Signer* sig, PK_Verifier* ver,
               const std::string& algo_name,
               double seconds, bool html)
   {
   static const u32bit MSG_SIZE = 16;
   byte msg[MSG_SIZE];
   Global_RNG::randomize(msg, MSG_SIZE);

   sig->update(msg, MSG_SIZE);
   SecureVector<byte> signature = sig->signature();
   u32bit runs = 0;
   u64bit clocks_used = 0;

   const u64bit ticks = get_ticks();
   while(clocks_used < seconds * ticks)
      {
      // feel free to tweak, but make sure this always runs when runs == 0
      if(runs % 100 == 0)
         {
         Global_RNG::randomize(msg, MSG_SIZE);
         sig->update(msg, MSG_SIZE);
         signature = sig->signature();
         }

      runs++;

      u64bit start = get_clock();
      ver->update(msg, MSG_SIZE);
      bool result = ver->check_signature(signature, signature.size());
      clocks_used += get_clock() - start;
      if(!result)
         throw Internal_Error("Signature check failed during benchmark");
      }

   delete sig;
   delete ver;

   print_result(html, runs, clocks_used, algo_name, "public operation");
   }

void bench_kas(PK_Key_Agreement* kas, const std::string& algo_name,
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
      Global_RNG::randomize(key, REMOTE_KEY_SIZE);

      u64bit start = get_clock();
      kas->derive_key(0, key, REMOTE_KEY_SIZE);
      clocks_used += get_clock() - start;
      }

   delete kas;

   print_result(html, runs, clocks_used, algo_name, "key agreement");
   }

/*************************************************
* Key loading procedures                         *
*************************************************/
RSA_PrivateKey* load_rsa_key(const std::string& file)
   {
   Private_Key* key = PKCS8::load_key(file);

   RSA_PrivateKey* rsakey = dynamic_cast<RSA_PrivateKey*>(key);

   if(rsakey == 0)
      throw Invalid_Argument(file + " doesn't have an RSA key in it!");

   return rsakey;
   }

#if !defined(BOTAN_NO_RW)
RW_PrivateKey load_rw_key(const std::string& file)
   {
   std::ifstream keyfile(file.c_str());
   if(!keyfile)
      throw Exception("Couldn't open the RW key file " + file);

   std::string e, p, q;

   std::getline(keyfile, e);
   std::getline(keyfile, p);
   std::getline(keyfile, q);

   RW_PrivateKey key(to_bigint(p), to_bigint(q), to_bigint(e));

   return key;
   }
#endif
