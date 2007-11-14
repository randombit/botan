#include <vector>
#include <string>
#include <cstdlib>

#include <botan/botan.h>
#include <botan/lookup.h>
#include <botan/look_pk.h>
#include <botan/filters.h>
#include <botan/randpool.h>
#include <botan/x931_rng.h>
#include <botan/rng.h>
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
      RNG_Filter(RandomNumberGenerator* r) : rng(r), buffer(1024)
         {
         Global_RNG::randomize(buffer, buffer.size());
         rng->add_entropy(buffer, buffer.size());
         }
      ~RNG_Filter() { delete rng; }
   private:
      RandomNumberGenerator* rng;
      SecureVector<byte> buffer;
   };

class KDF_Filter : public Filter
   {
   public:
      void write(const byte in[], u32bit len)
         { secret.push_back(in, len); }
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
   while(length)
      {
      u32bit gen = std::min(buffer.size(), length);
      rng->randomize(buffer, gen);
      length -= gen;
      }
   }

Filter* lookup_rng(const std::string& algname)
   {
   if(algname == "X9.31-RNG")
      return new RNG_Filter(new ANSI_X931_RNG);
   if(algname == "Randpool")
      return new RNG_Filter(new Randpool);
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
