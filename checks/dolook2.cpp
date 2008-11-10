#include <vector>
#include <string>
#include <cstdlib>

#include <botan/botan.h>
#include <botan/lookup.h>
#include <botan/filters.h>

#include <botan/hmac.h>
#include <botan/aes.h>
#include <botan/sha2_32.h>
#include <botan/sha2_64.h>

#if defined(BOTAN_HAS_RANDPOOL)
  #include <botan/randpool.h>
#endif

#if defined(BOTAN_HAS_HMAC_RNG)
  #include <botan/hmac_rng.h>
#endif

#if defined(BOTAN_HAS_X931_RNG)
  #include <botan/x931_rng.h>
  #include <botan/des.h>
#endif

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   #include <botan/auto_rng.h>
#endif

#include "common.h"
using namespace Botan;


/* A weird little hack to fit S2K algorithms into the validation suite
   You probably wouldn't ever want to actually use the S2K algorithms like
   this, the raw S2K interface is more convenient for actually using them
*/
class S2K_Filter : public Filter
   {
   public:
      void write(const byte in[], u32bit len)
         { passphrase += std::string(reinterpret_cast<const char*>(in), len); }
      void end_msg()
         {
         s2k->change_salt(salt, salt.size());
         s2k->set_iterations(iterations);
         SymmetricKey x = s2k->derive_key(outlen, passphrase);
         send(x.bits_of());
         }
      S2K_Filter(S2K* algo, const SymmetricKey& s, u32bit o, u32bit i)
         {
         s2k = algo;
         outlen = o;
         iterations = i;
         salt = s.bits_of();

         }
      ~S2K_Filter() { delete s2k; }
   private:
      std::string passphrase;
      S2K* s2k;
      SecureVector<byte> salt;
      u32bit outlen, iterations;
   };

/* Not too useful generally; just dumps random bits for benchmarking */
class RNG_Filter : public Filter
   {
   public:
      void write(const byte[], u32bit);

      RNG_Filter(RandomNumberGenerator* r) : rng(r) {}
      ~RNG_Filter() { delete rng; }
   private:
      RandomNumberGenerator* rng;
   };

class KDF_Filter : public Filter
   {
   public:
      void write(const byte in[], u32bit len)
         { secret.append(in, len); }
      void end_msg()
         {
         SymmetricKey x = kdf->derive_key(outlen,
                                          secret, secret.size(),
                                          salt, salt.size());
         send(x.bits_of(), x.length());
         }
      KDF_Filter(KDF* algo, const SymmetricKey& s, u32bit o)
         {
         kdf = algo;
         outlen = o;
         salt = s.bits_of();
         }
      ~KDF_Filter() { delete kdf; }
   private:
      SecureVector<byte> secret;
      SecureVector<byte> salt;
      KDF* kdf;
      u32bit outlen;
   };

Filter* lookup_s2k(const std::string& algname,
                   const std::vector<std::string>& params)
   {
   S2K* s2k = 0;

   try {
      s2k = get_s2k(algname);
      }
   catch(...) { }

   if(s2k)
      return new S2K_Filter(s2k, params[0], to_u32bit(params[1]),
                            to_u32bit(params[2]));
   return 0;
   }

void RNG_Filter::write(const byte[], u32bit length)
   {
   if(length)
      {
      SecureVector<byte> out(length);
      rng->randomize(out, out.size());
      send(out);
      }
   }

Filter* lookup_rng(const std::string& algname,
                   const std::string& key)
   {
   RandomNumberGenerator* prng = 0;

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   if(algname == "AutoSeeded")
      prng = new AutoSeeded_RNG;
#endif

#if defined(BOTAN_HAS_X931_RNG)
   if(algname == "X9.31-RNG(TripleDES)")
      prng = new ANSI_X931_RNG(new TripleDES,
                               new Fixed_Output_RNG(decode_hex(key)));
   else if(algname == "X9.31-RNG(AES-128)")
      prng = new ANSI_X931_RNG(new AES_128,
                               new Fixed_Output_RNG(decode_hex(key)));
   else if(algname == "X9.31-RNG(AES-192)")
      prng = new ANSI_X931_RNG(new AES_192,
                               new Fixed_Output_RNG(decode_hex(key)));
   else if(algname == "X9.31-RNG(AES-256)")
      prng = new ANSI_X931_RNG(new AES_256,
                               new Fixed_Output_RNG(decode_hex(key)));
#endif

#if defined(BOTAN_HAS_RANDPOOL)
   if(algname == "Randpool")
      {
      prng = new Randpool(new AES_256, new HMAC(new SHA_256));

      prng->add_entropy(reinterpret_cast<const byte*>(key.c_str()),
                        key.length());
      }
#endif

#if defined(BOTAN_HAS_X931_RNG)
   // these are used for benchmarking: AES-256/SHA-256 matches library
   // defaults, so benchmark reflects real-world performance (maybe)
   if(algname == "X9.31-RNG")
      {
      RandomNumberGenerator* rng =
#if defined(BOTAN_HAS_HMAC_RNG)
         new HMAC_RNG(new HMAC(new SHA_512), new HMAC(new SHA_256));
#elif defined(BOTAN_HAS_RANDPOOL)
         new Randpool(new AES_256, new HMAC(new SHA_256));
#endif

      prng = new ANSI_X931_RNG(new AES_256, rng);

      }
#endif

#if defined(BOTAN_HAS_HMAC_RNG)
   if(algname == "HMAC_RNG")
      {
      prng = new HMAC_RNG(new HMAC(new SHA_512), new HMAC(new SHA_256));
      }
#endif

   if(prng)
      {
      prng->add_entropy(reinterpret_cast<const byte*>(key.c_str()),
                        key.length());
      return new RNG_Filter(prng);
      }

   return 0;
   }

Filter* lookup_kdf(const std::string& algname, const std::string& salt,
                   const std::string& params)
   {
   KDF* kdf = 0;
   try {
      kdf = get_kdf(algname);
      }
   catch(...) { return 0; }

   if(kdf)
      return new KDF_Filter(kdf, salt, to_u32bit(params));
   return 0;
   }
