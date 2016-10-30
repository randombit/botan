/*
* (C) 2009,2010,2014,2015 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"
#include "../tests/test_rng.h" // FIXME

#include <sstream>
#include <iomanip>
#include <chrono>
#include <functional>

// Always available:
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/cipher_mode.h>
#include <botan/entropy_src.h>

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
  #include <botan/auto_rng.h>
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
  #include <botan/system_rng.h>
#endif

#if defined(BOTAN_HAS_HMAC_DRBG)
  #include <botan/hmac_drbg.h>
#endif

#if defined(BOTAN_HAS_HMAC_RNG)
  #include <botan/hmac_rng.h>
#endif

#if defined(BOTAN_HAS_FPE_FE1)
  #include <botan/fpe_fe1.h>
#endif

#if defined(BOTAN_HAS_COMPRESSION)
  #include <botan/compression.h>
#endif

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
  #include <botan/pkcs8.h>
  #include <botan/pubkey.h>
  #include <botan/x509_key.h>
#endif

#if defined(BOTAN_HAS_NUMBERTHEORY)
  #include <botan/numthry.h>
#endif

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_ECKCDSA)
  #include <botan/eckcdsa.h>
#endif

#if defined(BOTAN_HAS_ECGDSA)
  #include <botan/ecgdsa.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include <botan/dh.h>
#endif

#if defined(BOTAN_HAS_CURVE_25519)
  #include <botan/curve25519.h>
#endif

#if defined(BOTAN_HAS_ECDH)
  #include <botan/ecdh.h>
#endif

#if defined(BOTAN_HAS_MCELIECE)
  #include <botan/mceliece.h>
#endif

#if defined(BOTAN_HAS_NEWHOPE) && defined(BOTAN_HAS_CHACHA)
  #include <botan/newhope.h>
  #include <botan/chacha.h>
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
  #include <botan/ec_group.h>
#endif

namespace Botan_CLI {

namespace {

class Timer
   {
   public:
      static uint64_t get_clock() // returns nanoseconds with arbitrary epoch
         {
         auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
         return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
         }

      Timer(const std::string& name, uint64_t event_mult = 1) :
         m_name(name), m_event_mult(event_mult) {}

      Timer(const std::string& what,
            const std::string& provider,
            const std::string& doing,
            uint64_t event_mult = 1) :
         m_name(what + (provider.empty() ? provider : " [" + provider + "]")),
         m_doing(doing),
         m_event_mult(event_mult) {}

      void start() { stop(); m_timer_start = get_clock(); }

      void stop()
         {
         if(m_timer_start)
            {
            const uint64_t now = get_clock();

            if(now > m_timer_start)
               {
               uint64_t dur = now - m_timer_start;

               m_time_used += dur;

               if(m_event_count == 0)
                  {
                  m_min_time = m_max_time = dur;
                  }
               else
                  {
                  m_max_time = std::max(m_max_time, dur);
                  m_min_time = std::min(m_min_time, dur);
                  }
               }

            m_timer_start = 0;
            ++m_event_count;
            }
         }

      bool under(std::chrono::milliseconds msec)
         {
         return (milliseconds() < msec.count());
         }

      struct Timer_Scope
         {
         public:
            explicit Timer_Scope(Timer& timer) : m_timer(timer) { m_timer.start(); }
            ~Timer_Scope() { m_timer.stop(); }
         private:
            Timer& m_timer;
         };

      template<typename F>
      auto run(F f) -> decltype(f())
         {
         Timer_Scope timer(*this);
         return f();
         }

      template<typename F>
      void run_until_elapsed(std::chrono::milliseconds msec, F f)
         {
         while(this->under(msec))
            {
            run(f);
            }
         }

      uint64_t value() const { return m_time_used; }
      double seconds() const { return milliseconds() / 1000.0; }
      double milliseconds() const { return value() / 1000000.0; }

      double ms_per_event() const { return milliseconds() / events(); }
      double seconds_per_event() const { return seconds() / events(); }

      uint64_t event_mult() const { return m_event_mult; }
      uint64_t events() const { return m_event_count * m_event_mult; }
      const std::string& get_name() const { return m_name; }
      const std::string& doing() const { return m_doing; }

      uint64_t min_time() const { return m_min_time; }
      uint64_t max_time() const { return m_max_time; }

      static std::string result_string_bps(const Timer& t);
      static std::string result_string_ops(const Timer& t);
   private:
      std::string m_name, m_doing;
      uint64_t m_time_used = 0, m_timer_start = 0;
      uint64_t m_event_count = 0, m_event_mult = 0;

      uint64_t m_max_time = 0, m_min_time = 0;
   };

std::string Timer::result_string_bps(const Timer& timer)
   {
   const size_t MiB = 1024*1024;

   const double MiB_total = static_cast<double>(timer.events()) / MiB;
   const double MiB_per_sec = MiB_total / timer.seconds();

   std::ostringstream oss;
   oss << timer.get_name();

   if(!timer.doing().empty())
      oss << " " << timer.doing();

   oss << " " << std::fixed << std::setprecision(3)
       << MiB_per_sec << " MiB/sec"
       << " (" << MiB_total << " MiB in " << timer.milliseconds() << " ms)\n";

   return oss.str();
   }

std::string Timer::result_string_ops(const Timer& timer)
   {
   std::ostringstream oss;

   const double events_per_second = timer.events() / timer.seconds();

   oss << timer.get_name() << " ";

   if(timer.events() == 0)
      {
      oss << "no events\n";
      }
   else
      {
      oss << static_cast<uint64_t>(events_per_second)
          << ' ' << timer.doing() << "/sec; "
          << std::setprecision(2) << std::fixed
          << timer.ms_per_event() << " ms/op"
          << " (" << timer.events() << " " << (timer.events() == 1 ? "op" : "ops")
          << " in " << timer.milliseconds() << " ms)\n";
      }

   return oss.str();
   }

std::vector<std::string> default_benchmark_list()
   {
   /*
   This is not intended to be exhaustive: it just hits the high
   points of the most interesting or widely used algorithms.
   */

   return {
      /* Block ciphers */
      "AES-128",
      "AES-192",
      "AES-256",
      "Blowfish",
      "CAST-128",
      "CAST-256",
      "DES",
      "TripleDES",
      "IDEA",
      "KASUMI",
      "Noekeon",
      "Serpent",
      "Threefish-512",
      "Twofish",

      /* Cipher modes */
      "AES-128/CBC",
      "AES-128/CTR-BE",
      "AES-128/EAX",
      "AES-128/OCB",
      "AES-128/GCM",
      "AES-128/XTS",

      "Serpent/CBC",
      "Serpent/CTR-BE",
      "Serpent/EAX",
      "Serpent/OCB",
      "Serpent/GCM",
      "Serpent/XTS",

      "ChaCha20Poly1305",

      /* Stream ciphers */
      "RC4",
      "Salsa20",

      /* Hashes */
      "Tiger",
      "RIPEMD-160",
      "SHA-160",
      "SHA-256",
      "SHA-512",
      "Skein-512",
      "Keccak-1600(512)",
      "Whirlpool",

      /* MACs */
      "CMAC(AES-128)",
      "HMAC(SHA-256)",

      /* Misc */
      "random_prime"

      /* pubkey */
      "RSA",
      "DH",
      "ECDH",
      "ECDSA",
      "ECKCDSA",
      "ECGDSA",
      "Curve25519",
      "McEliece",
      "NEWHOPE"
      };
   }

}

class Speed final : public Command
   {
   public:
      Speed() : Command("speed --msec=300 --provider= --buf-size=4096 *algos") {}

      void go() override
         {
         std::chrono::milliseconds msec(get_arg_sz("msec"));
         const size_t buf_size = get_arg_sz("buf-size");
         const std::string provider = get_arg("provider");

         std::vector<std::string> algos = get_arg_list("algos");
         const bool using_defaults = (algos.empty());
         if(using_defaults)
            algos = default_benchmark_list();

         for(auto algo : algos)
            {
            using namespace std::placeholders;

            if(auto enc = Botan::get_cipher_mode(algo, Botan::ENCRYPTION))
               {
               auto dec = Botan::get_cipher_mode(algo, Botan::DECRYPTION);
               bench_cipher_mode(*enc, *dec, msec, buf_size);
               }
            else if(Botan::BlockCipher::providers(algo).size() > 0)
               {
               bench_providers_of<Botan::BlockCipher>(
                  algo, provider, msec, buf_size,
                  std::bind(&Speed::bench_block_cipher, this, _1, _2, _3, _4));
               }
            else if(Botan::StreamCipher::providers(algo).size() > 0)
               {
               bench_providers_of<Botan::StreamCipher>(
                  algo, provider, msec, buf_size,
                  std::bind(&Speed::bench_stream_cipher, this, _1, _2, _3, _4));
               }
            else if(Botan::HashFunction::providers(algo).size() > 0)
               {
               bench_providers_of<Botan::HashFunction>(
                  algo, provider, msec, buf_size,
                  std::bind(&Speed::bench_hash, this, _1, _2, _3, _4));
               }
            else if(Botan::MessageAuthenticationCode::providers(algo).size() > 0)
               {
               bench_providers_of<Botan::MessageAuthenticationCode>(
                  algo, provider, msec, buf_size,
                  std::bind(&Speed::bench_mac, this, _1, _2, _3, _4));
               }
#if defined(BOTAN_HAS_RSA)
            else if(algo == "RSA")
               {
               bench_rsa(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_ECDSA)
            else if(algo == "ECDSA")
               {
               bench_ecdsa(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_ECKCDSA)
            else if(algo == "ECKCDSA")
               {
               bench_eckcdsa(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_ECGDSA)
            else if(algo == "ECGDSA")
               {
               bench_ecgdsa(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
            else if(algo == "DH")
               {
               bench_dh(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_ECDH)
            else if(algo == "ECDH")
               {
               bench_ecdh(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_CURVE_25519)
            else if(algo == "Curve25519")
               {
               bench_curve25519(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_MCELIECE)
            else if(algo == "McEliece")
               {
               bench_mceliece(provider, msec);
               }
#endif
#if defined(BOTAN_HAS_NEWHOPE) && defined(BOTAN_HAS_CHACHA)
            else if(algo == "NEWHOPE")
               {
               bench_newhope(provider, msec);
               }
#endif

#if defined(BOTAN_HAS_NUMBERTHEORY)
            else if(algo == "random_prime")
               {
               bench_random_prime(msec);
               }
            else if(algo == "inverse_mod")
               {
               bench_inverse_mod(msec);
               }
#endif

#if defined(BOTAN_HAS_FPE_FE1)
            else if(algo == "fpe_fe1")
               {
               bench_fpe_fe1(msec);
               }
#endif
#if defined(BOTAN_HAS_ECC_GROUP)
            else if(algo == "os2ecp")
               {
               bench_os2ecp(msec);
               }
#endif
            else if(algo == "RNG")
               {
#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
               Botan::AutoSeeded_RNG auto_rng;
               bench_rng(auto_rng, "AutoSeeded_RNG (periodic reseed)", msec, buf_size);
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
               bench_rng(Botan::system_rng(), "System_RNG", msec, buf_size);
#endif

#if defined(BOTAN_HAS_HMAC_DRBG)
               for(std::string hash : { "SHA-256", "SHA-384", "SHA-512" })
                  {
                  Botan::HMAC_DRBG hmac_drbg(hash);
                  bench_rng(hmac_drbg, hmac_drbg.name(), msec, buf_size);
                  }
#endif
               }
            else if(algo == "entropy")
               {
               bench_entropy_sources(msec);
               }
            else
               {
               if(verbose() || !using_defaults)
                  {
                  error_output() << "Unknown algorithm '" << algo << "'\n";
                  }
               }
            }
         }

   private:

      template<typename T>
      using bench_fn = std::function<void (T&,
                                           std::string,
                                           std::chrono::milliseconds,
                                           size_t)>;

      template<typename T>
      void bench_providers_of(const std::string& algo,
                              const std::string& provider, /* user request, if any */
                              const std::chrono::milliseconds runtime,
                              size_t buf_size,
                              bench_fn<T> bench_one)
         {
         for(auto&& prov : T::providers(algo))
            {
            if(provider.empty() || provider == prov)
               {
               auto p = T::create(algo, prov);

               if(p)
                  {
                  bench_one(*p, prov, runtime, buf_size);
                  }
               }
            }
         }

      void bench_block_cipher(Botan::BlockCipher& cipher,
                              const std::string& provider,
                              std::chrono::milliseconds runtime,
                              size_t buf_size)
         {
         std::vector<uint8_t> buffer(buf_size * cipher.block_size());

         Timer encrypt_timer(cipher.name(), provider, "encrypt", buffer.size());
         Timer decrypt_timer(cipher.name(), provider, "decrypt", buffer.size());
         Timer ks_timer(cipher.name(), provider, "key schedule");

         const Botan::SymmetricKey key(rng(), cipher.maximum_keylength());
         ks_timer.run([&] { cipher.set_key(key); });

         encrypt_timer.run_until_elapsed(runtime, [&] { cipher.encrypt(buffer); });
         output() << Timer::result_string_bps(encrypt_timer);

         decrypt_timer.run_until_elapsed(runtime, [&] { cipher.decrypt(buffer); });
         output() << Timer::result_string_bps(decrypt_timer);
         }

      void bench_stream_cipher(Botan::StreamCipher& cipher,
                               const std::string& provider,
                               const std::chrono::milliseconds runtime,
                               size_t buf_size)
         {
         Botan::secure_vector<uint8_t> buffer = rng().random_vec(buf_size);

         Timer encrypt_timer(cipher.name(), provider, "encrypt", buffer.size());

         const Botan::SymmetricKey key(rng(), cipher.maximum_keylength());
         cipher.set_key(key);

         while(encrypt_timer.under(runtime))
            {
            encrypt_timer.run([&] { cipher.encipher(buffer); });
            }

         output() << Timer::result_string_bps(encrypt_timer);
         }

      void bench_hash(Botan::HashFunction& hash,
                      const std::string& provider,
                      const std::chrono::milliseconds runtime,
                      size_t buf_size)
         {
         Botan::secure_vector<uint8_t> buffer = rng().random_vec(buf_size);

         Timer timer(hash.name(), provider, "hash", buffer.size());
         timer.run_until_elapsed(runtime, [&] { hash.update(buffer); });
         output() << Timer::result_string_bps(timer);
         }

      void bench_mac(Botan::MessageAuthenticationCode& mac,
                     const std::string& provider,
                     const std::chrono::milliseconds runtime,
                     size_t buf_size)
         {
         Botan::secure_vector<uint8_t> buffer = rng().random_vec(buf_size);

         const Botan::SymmetricKey key(rng(), mac.maximum_keylength());
         mac.set_key(key);

         Timer timer(mac.name(), provider, "mac", buffer.size());
         timer.run_until_elapsed(runtime, [&] { mac.update(buffer); });
         output() << Timer::result_string_bps(timer);
         }

      void bench_cipher_mode(Botan::Cipher_Mode& enc,
                             Botan::Cipher_Mode& dec,
                             const std::chrono::milliseconds runtime,
                             size_t buf_size)
         {
         Botan::secure_vector<uint8_t> buffer = rng().random_vec(buf_size);

         Timer encrypt_timer(enc.name(), enc.provider(), "encrypt", buffer.size());
         Timer decrypt_timer(enc.name(), enc.provider(), "decrypt", buffer.size());
         Timer ks_timer(enc.name(), enc.provider(), "key schedule");
         Timer iv_timer(enc.name(), enc.provider(), "iv setup");

         const Botan::SymmetricKey key(rng(), enc.key_spec().maximum_keylength());

         ks_timer.run([&] { enc.set_key(key); });
         ks_timer.run([&] { dec.set_key(key); });

         Botan::secure_vector<uint8_t> iv = rng().random_vec(enc.default_nonce_length());

         while(encrypt_timer.under(runtime) && decrypt_timer.under(runtime))
            {
            // Must run in this order, or AEADs will reject the ciphertext
            iv_timer.run([&] { enc.start(iv); });
            encrypt_timer.run([&] { enc.finish(buffer); });

            iv_timer.run([&] { dec.start(iv); });
            decrypt_timer.run([&] { dec.finish(buffer); });

            if(iv.size() > 0)
               iv[0] += 1;
            }

         output() << Timer::result_string_ops(ks_timer);
         output() << Timer::result_string_ops(iv_timer);
         output() << Timer::result_string_bps(encrypt_timer);
         output() << Timer::result_string_bps(decrypt_timer);
         }

      void bench_rng(Botan::RandomNumberGenerator& rng,
                     const std::string& rng_name,
                     const std::chrono::milliseconds runtime,
                     size_t buf_size)
         {
         Botan::secure_vector<uint8_t> buffer(buf_size);

#if defined(BOTAN_HAS_SYSTEM_RNG)
         rng.reseed_from_rng(Botan::system_rng(), 256);
#endif

         Timer timer(rng_name, "", "generate", buffer.size());
         timer.run_until_elapsed(runtime, [&] { rng.randomize(buffer.data(), buffer.size()); });
         output() << Timer::result_string_bps(timer);
         }

      void bench_entropy_sources(const std::chrono::milliseconds)
         {
         Botan::Entropy_Sources& srcs = Botan::Entropy_Sources::global_sources();

         for(auto src : srcs.enabled_sources())
            {
            size_t entropy_bits = 0;
            Botan_Tests::SeedCapturing_RNG rng;

            Timer timer(src, "", "bytes");
            timer.run([&] { entropy_bits = srcs.poll_just(rng, src); });

#if defined(BOTAN_HAS_COMPRESSION)
            std::unique_ptr<Botan::Compression_Algorithm> comp(Botan::make_compressor("zlib"));
            Botan::secure_vector<uint8_t> compressed;

            if(comp)
               {
               compressed.assign(rng.seed_material().begin(), rng.seed_material().end());
               comp->start(9);
               comp->finish(compressed);
               }
#endif

            output() << "Entropy source " << src << " output " << rng.seed_material().size() << " bytes"
                     << " estimated entropy " << entropy_bits
                     << " in " << timer.milliseconds() << " ms";

#if defined(BOTAN_HAS_COMPRESSION)
            if(compressed.size() > 0)
               {
               output() << " output compressed to " << compressed.size() << " bytes";
               }
#endif

            output() << " total samples " << rng.samples() << "\n";
            }
         }

#if defined(BOTAN_HAS_ECC_GROUP)
      void bench_os2ecp(const std::chrono::milliseconds runtime)
         {
         Timer uncmp_timer("OS2ECP uncompressed");
         Timer cmp_timer("OS2ECP compressed");

         const Botan::EC_Group group("secp256r1");
         const Botan::CurveGFp& curve = group.get_curve();

         while(uncmp_timer.under(runtime) && cmp_timer.under(runtime))
            {
            const Botan::BigInt k(rng(), 256);
            const Botan::PointGFp p = group.get_base_point() * k;
            const Botan::secure_vector<uint8_t> os_cmp = Botan::EC2OSP(p, Botan::PointGFp::COMPRESSED);
            const Botan::secure_vector<uint8_t> os_uncmp = Botan::EC2OSP(p, Botan::PointGFp::UNCOMPRESSED);

            uncmp_timer.run([&] { OS2ECP(os_uncmp, curve); });
            cmp_timer.run([&] { OS2ECP(os_cmp, curve); });
            }

         output() << Timer::result_string_ops(uncmp_timer);
         output() << Timer::result_string_ops(cmp_timer);
         }

#endif

#if defined(BOTAN_HAS_FPE_FE1)

      void bench_fpe_fe1(const std::chrono::milliseconds runtime)
         {
         const Botan::BigInt n = 1000000000000000;

         Timer enc_timer("FPE_FE1 encrypt");
         Timer dec_timer("FPE_FE1 decrypt");

         const Botan::SymmetricKey key(rng(), 32);
         const std::vector<uint8_t> tweak(8); // 8 zeros

         Botan::BigInt x = 1;

         while(enc_timer.under(runtime))
            {
            enc_timer.start();
            x = Botan::FPE::fe1_encrypt(n, x, key, tweak);
            enc_timer.stop();
            }

         for(size_t i = 0; i != enc_timer.events(); ++i)
            {
            dec_timer.start();
            x = Botan::FPE::fe1_decrypt(n, x, key, tweak);
            dec_timer.stop();
            }

         BOTAN_ASSERT(x == 1, "FPE works");

         output() << Timer::result_string_ops(enc_timer);
         output() << Timer::result_string_ops(dec_timer);
         }
#endif

#if defined(BOTAN_HAS_NUMBERTHEORY)

      void bench_inverse_mod(const std::chrono::milliseconds runtime)
         {
         Botan::BigInt p;
         p.set_bit(521);
         p--;

         Timer invmod_timer("inverse_mod");
         Timer monty_timer("montgomery_inverse");
         Timer ct_invmod_timer("ct_inverse_mod");
         Timer powm_timer("exponentiation");

         Botan::Fixed_Exponent_Power_Mod powm_p(p - 2, p);

         while(invmod_timer.under(runtime))
            {
            const Botan::BigInt x(rng(), p.bits() - 1);

            const Botan::BigInt x_inv1 = invmod_timer.run([&]{
               return Botan::inverse_mod(x + p, p);
               });

            const Botan::BigInt x_inv2 = monty_timer.run([&]{
               return Botan::normalized_montgomery_inverse(x, p);
               });

            const Botan::BigInt x_inv3 = ct_invmod_timer.run([&]{
               return Botan::ct_inverse_mod_odd_modulus(x, p);
               });

            const Botan::BigInt x_inv4 = powm_timer.run([&]{
               return powm_p(x);
               });

            BOTAN_ASSERT_EQUAL(x_inv1, x_inv2, "Same result");
            BOTAN_ASSERT_EQUAL(x_inv1, x_inv3, "Same result");
            BOTAN_ASSERT_EQUAL(x_inv1, x_inv4, "Same result");
            }

         output() << Timer::result_string_ops(invmod_timer);
         output() << Timer::result_string_ops(monty_timer);
         output() << Timer::result_string_ops(ct_invmod_timer);
         output() << Timer::result_string_ops(powm_timer);
         }

      void bench_random_prime(const std::chrono::milliseconds runtime)
         {
         const size_t coprime = 65537; // simulates RSA key gen

         for(size_t bits : { 1024, 1536 })
            {
            Timer genprime_timer("random_prime " + std::to_string(bits));
            Timer is_prime_timer("is_prime " + std::to_string(bits));

            while(genprime_timer.under(runtime) && is_prime_timer.under(runtime))
               {
               const Botan::BigInt p = genprime_timer.run([&] {
                  return Botan::random_prime(rng(), bits, coprime); });

               const bool ok = is_prime_timer.run([&] {
                  return Botan::is_prime(p, rng(), 64, true);
               });

               if(!ok)
                  {
                  error_output() << "Generated prime " << p
                                 << " which then failed primality test";
                  }

               // Now test p+2, p+4, ... which may or may not be prime
               for(size_t i = 2; i != 64; i += 2)
                  {
                  is_prime_timer.run([&] { Botan::is_prime(p, rng(), 64, true); });
                  }
               }

            output() << Timer::result_string_ops(genprime_timer);
            output() << Timer::result_string_ops(is_prime_timer);
            }
         }
#endif

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
      void bench_pk_enc(const Botan::Private_Key& key,
                        const std::string& nm,
                        const std::string& provider,
                        const std::string& padding,
                        std::chrono::milliseconds msec)
         {
         std::vector<uint8_t> plaintext, ciphertext;

         Botan::PK_Encryptor_EME enc(key, rng(), padding, provider);
         Botan::PK_Decryptor_EME dec(key, rng(), padding, provider);

         Timer enc_timer(nm, provider, padding + " encrypt");
         Timer dec_timer(nm, provider, padding + " decrypt");

         while(enc_timer.under(msec) || dec_timer.under(msec))
            {
            // Generate a new random ciphertext to decrypt
            if(ciphertext.empty() || enc_timer.under(msec))
               {
               plaintext = unlock(rng().random_vec(enc.maximum_input_size()));
               ciphertext = enc_timer.run([&] { return enc.encrypt(plaintext, rng()); });
               }

            if(dec_timer.under(msec))
               {
               auto dec_pt = dec_timer.run([&] { return dec.decrypt(ciphertext); });

               if(dec_pt != plaintext) // sanity check
                  {
                  error_output() << "Bad roundtrip in PK encrypt/decrypt bench\n";
                  }
               }
            }

         output() << Timer::result_string_ops(enc_timer);
         output() << Timer::result_string_ops(dec_timer);
         }

      void bench_pk_ka(const Botan::PK_Key_Agreement_Key& key1,
                       const Botan::PK_Key_Agreement_Key& key2,
                       const std::string& nm,
                       const std::string& provider,
                       const std::string& kdf,
                       std::chrono::milliseconds msec)
         {
         Botan::PK_Key_Agreement ka1(key1, rng(), kdf, provider);
         Botan::PK_Key_Agreement ka2(key2, rng(), kdf, provider);

         const std::vector<uint8_t> ka1_pub = key1.public_value();
         const std::vector<uint8_t> ka2_pub = key2.public_value();

         Timer ka_timer(nm, provider, "key agreements");

         while(ka_timer.under(msec))
            {
            Botan::SymmetricKey symkey1 = ka_timer.run([&] { return ka1.derive_key(32, ka2_pub); });
            Botan::SymmetricKey symkey2 = ka_timer.run([&] { return ka2.derive_key(32, ka1_pub); });

            if(symkey1 != symkey1)
               {
               error_output() << "Key agreement mismatch in PK bench\n";
               }
            }

         output() << Timer::result_string_ops(ka_timer);
         }

      void bench_pk_kem(const Botan::Private_Key& key,
                        const std::string& nm,
                        const std::string& provider,
                        const std::string& kdf,
                        std::chrono::milliseconds msec)
         {
         Botan::PK_KEM_Decryptor dec(key, rng(), kdf, provider);
         Botan::PK_KEM_Encryptor enc(key, rng(), kdf, provider);

         Timer kem_enc_timer(nm, provider, "KEM encrypt");
         Timer kem_dec_timer(nm, provider, "KEM decrypt");

         while(kem_enc_timer.under(msec) && kem_dec_timer.under(msec))
            {
            Botan::secure_vector<uint8_t> encap_key, enc_shared_key;
            Botan::secure_vector<uint8_t> salt = rng().random_vec(16);

            kem_enc_timer.start();
            enc.encrypt(encap_key, enc_shared_key, 64, rng(), salt);
            kem_enc_timer.stop();

            kem_dec_timer.start();
            Botan::secure_vector<uint8_t> dec_shared_key = dec.decrypt(encap_key, 64, salt);
            kem_dec_timer.stop();

            if(enc_shared_key != dec_shared_key)
               {
               error_output() << "KEM mismatch in PK bench\n";
               }
            }

         output() << Timer::result_string_ops(kem_enc_timer);
         output() << Timer::result_string_ops(kem_dec_timer);
         }

      void bench_pk_sig(const Botan::Private_Key& key,
                        const std::string& nm,
                        const std::string& provider,
                        const std::string& padding,
                        std::chrono::milliseconds msec)
         {
         std::vector<uint8_t> message, signature, bad_signature;

         Botan::PK_Signer   sig(key, rng(), padding, Botan::IEEE_1363, provider);
         Botan::PK_Verifier ver(key, padding, Botan::IEEE_1363, provider);

         Timer sig_timer(nm, provider, padding + " sign");
         Timer ver_timer(nm, provider, padding + " verify");

         while(ver_timer.under(msec) || sig_timer.under(msec))
            {
            if(signature.empty() || sig_timer.under(msec))
               {
               /*
               Length here is kind of arbitrary, but 48 bytes fits into a single
               hash block so minimizes hashing overhead versus the PK op itself.
               */
               message = unlock(rng().random_vec(48));

               signature = sig_timer.run([&] { return sig.sign_message(message, rng()); });

               bad_signature = signature;
               bad_signature[rng().next_byte() % bad_signature.size()] ^= rng().next_nonzero_byte();
               }

            if(ver_timer.under(msec))
               {
               const bool verified = ver_timer.run([&] {
                  return ver.verify_message(message, signature); });

               if(!verified)
                  {
                  error_output() << "Correct signature rejected in PK signature bench\n";
                  }

               const bool verified_bad = ver_timer.run([&] {
                  return ver.verify_message(message, bad_signature); });

               if(verified_bad)
                  {
                  error_output() << "Bad signature accepted in PK signature bench\n";
                  }
               }
            }

         output() << Timer::result_string_ops(sig_timer);
         output() << Timer::result_string_ops(ver_timer);
         }
#endif

#if defined(BOTAN_HAS_RSA)
      void bench_rsa(const std::string& provider,
                     std::chrono::milliseconds msec)
         {
         for(size_t keylen : { 1024, 2048, 3072, 4096 })
            {
            const std::string nm = "RSA-" + std::to_string(keylen);

            Timer keygen_timer(nm, provider, "keygen");

            std::unique_ptr<Botan::Private_Key> key(keygen_timer.run([&] {
               return new Botan::RSA_PrivateKey(rng(), keylen);
               }));

            output() << Timer::result_string_ops(keygen_timer);

            // Using PKCS #1 padding so OpenSSL provider can play along
            bench_pk_enc(*key, nm, provider, "EME-PKCS1-v1_5", msec);
            bench_pk_enc(*key, nm, provider, "OAEP(SHA-1)", msec);

            bench_pk_sig(*key, nm, provider, "EMSA-PKCS1-v1_5(SHA-1)", msec);
            bench_pk_sig(*key, nm, provider, "PSSR(SHA-256)", msec);
            }
         }
#endif

#if defined(BOTAN_HAS_ECDSA)
      void bench_ecdsa(const std::string& provider,
                       std::chrono::milliseconds msec)
         {
         for(std::string grp : { "secp256r1", "secp384r1", "secp521r1" })
            {
            const std::string nm = "ECDSA-" + grp;

            Timer keygen_timer(nm, provider, "keygen");

            std::unique_ptr<Botan::Private_Key> key(keygen_timer.run([&] {
               return new Botan::ECDSA_PrivateKey(rng(), Botan::EC_Group(grp));
               }));

            output() << Timer::result_string_ops(keygen_timer);
            bench_pk_sig(*key, nm, provider, "EMSA1(SHA-256)", msec);
            }
         }
#endif
      
#if defined(BOTAN_HAS_ECKCDSA)
      void bench_eckcdsa(const std::string& provider,
                       std::chrono::milliseconds msec)
         {
         for(std::string grp : { "secp256r1", "secp384r1", "secp521r1" })
            {
            const std::string nm = "ECKCDSA-" + grp;

            Timer keygen_timer(nm, provider, "keygen");

            std::unique_ptr<Botan::Private_Key> key(keygen_timer.run([&] {
               return new Botan::ECKCDSA_PrivateKey(rng(), Botan::EC_Group(grp));
               }));

            output() << Timer::result_string_ops(keygen_timer);
            bench_pk_sig(*key, nm, provider, "EMSA1(SHA-256)", msec);
            }
         }
#endif
      
#if defined(BOTAN_HAS_ECGDSA)
      void bench_ecgdsa(const std::string& provider,
                       std::chrono::milliseconds msec)
         {
         for(std::string grp : { "secp256r1", "secp384r1", "secp521r1" })
            {
            const std::string nm = "ECGDSA-" + grp;

            Timer keygen_timer(nm, provider, "keygen");

            std::unique_ptr<Botan::Private_Key> key(keygen_timer.run([&] {
               return new Botan::ECGDSA_PrivateKey(rng(), Botan::EC_Group(grp));
               }));

            output() << Timer::result_string_ops(keygen_timer);
            bench_pk_sig(*key, nm, provider, "EMSA1(SHA-256)", msec);
            }
         }
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
      void bench_dh(const std::string& provider,
                    std::chrono::milliseconds msec)
         {
         for(size_t bits : { 1024, 2048, 3072 })
            {
            const std::string grp = "modp/ietf/" + std::to_string(bits);
            const std::string nm = "DH-" + std::to_string(bits);

            Timer keygen_timer(nm, provider, "keygen");

            std::unique_ptr<Botan::PK_Key_Agreement_Key> key1(keygen_timer.run([&] {
               return new Botan::DH_PrivateKey(rng(), Botan::DL_Group(grp));
               }));
            std::unique_ptr<Botan::PK_Key_Agreement_Key> key2(keygen_timer.run([&] {
               return new Botan::DH_PrivateKey(rng(), Botan::DL_Group(grp));
               }));

            output() << Timer::result_string_ops(keygen_timer);
            bench_pk_ka(*key1, *key2, nm, provider, "KDF2(SHA-256)", msec);
            }
         }
#endif

#if defined(BOTAN_HAS_ECDH)
      void bench_ecdh(const std::string& provider,
                      std::chrono::milliseconds msec)
         {
         for(std::string grp : { "secp256r1", "secp384r1", "secp521r1" })
            {
            const std::string nm = "ECDH-" + grp;

            Timer keygen_timer(nm, provider, "keygen");

            std::unique_ptr<Botan::PK_Key_Agreement_Key> key1(keygen_timer.run([&] {
               return new Botan::ECDH_PrivateKey(rng(), Botan::EC_Group(grp));
               }));
            std::unique_ptr<Botan::PK_Key_Agreement_Key> key2(keygen_timer.run([&] {
               return new Botan::ECDH_PrivateKey(rng(), Botan::EC_Group(grp));
               }));

            output() << Timer::result_string_ops(keygen_timer);
            bench_pk_ka(*key1, *key2, nm, provider, "KDF2(SHA-256)", msec);
            }
         }
#endif

#if defined(BOTAN_HAS_CURVE_25519)
      void bench_curve25519(const std::string& provider,
                            std::chrono::milliseconds msec)
         {
         const std::string nm = "Curve25519";

         Timer keygen_timer(nm, provider, "keygen");

         std::unique_ptr<Botan::PK_Key_Agreement_Key> key1(keygen_timer.run([&] {
            return new Botan::Curve25519_PrivateKey(rng());
            }));
         std::unique_ptr<Botan::PK_Key_Agreement_Key> key2(keygen_timer.run([&] {
            return new Botan::Curve25519_PrivateKey(rng());
            }));

         output() << Timer::result_string_ops(keygen_timer);
         bench_pk_ka(*key1, *key2, nm, provider, "KDF2(SHA-256)", msec);
         }
#endif

#if defined(BOTAN_HAS_MCELIECE)
      void bench_mceliece(const std::string& provider,
                          std::chrono::milliseconds msec)
         {
         /*
         SL=80 n=1632 t=33 - 59 KB pubkey 140 KB privkey
         SL=107 n=2480 t=45 - 128 KB pubkey 300 KB privkey
         SL=128 n=2960 t=57 - 195 KB pubkey 459 KB privkey
         SL=147 n=3408 t=67 - 265 KB pubkey 622 KB privkey
         SL=191 n=4624 t=95 - 516 KB pubkey 1234 KB privkey
         SL=256 n=6624 t=115 - 942 KB pubkey 2184 KB privkey
         */

         const std::vector<std::pair<size_t, size_t>> mce_params = {
            { 2480, 45 },
            { 2960, 57 },
            { 3408, 67 },
            { 4624, 95 },
            { 6624, 115 }
         };

         for(auto params : mce_params)
            {
            size_t n = params.first;
            size_t t = params.second;

            const std::string nm = "McEliece-" + std::to_string(n) + "," + std::to_string(t) +
               " (WF=" + std::to_string(Botan::mceliece_work_factor(n, t)) + ")";

            Timer keygen_timer(nm, provider, "keygen");

            std::unique_ptr<Botan::Private_Key> key(keygen_timer.run([&] {
                  return new Botan::McEliece_PrivateKey(rng(), n, t);
               }));

            output() << Timer::result_string_ops(keygen_timer);
            bench_pk_kem(*key, nm, provider, "KDF2(SHA-256)", msec);
            }
         }
#endif

#if defined(BOTAN_HAS_NEWHOPE) && defined(BOTAN_HAS_CHACHA)
      void bench_newhope(const std::string& /*provider*/,
                         std::chrono::milliseconds msec)
         {
         const std::string nm = "NEWHOPE";

         Timer keygen_timer(nm, "", "keygen");
         Timer shareda_timer(nm, "", "shareda");
         Timer sharedb_timer(nm, "", "sharedb");

         class ChaCha20_RNG : public Botan::RandomNumberGenerator
            {
            public:
               std::string name() const override { return "ChaCha20_RNG"; }
               void clear() override { /* ignored */ }

               void randomize(uint8_t out[], size_t len) override
                  {
                  Botan::clear_mem(out, len);
                  m_chacha.cipher1(out, len);
                  }

               bool is_seeded() const override { return true; }

               void add_entropy(const uint8_t[], size_t) override { /* ignored */ }

               ChaCha20_RNG(const Botan::secure_vector<uint8_t>& seed)
                  {
                  m_chacha.set_key(seed);
                  }

            private:
               Botan::ChaCha m_chacha;
            };

         ChaCha20_RNG nh_rng(rng().random_vec(32));

         while(sharedb_timer.under(msec))
            {
            std::vector<uint8_t> send_a(NEWHOPE_SENDABYTES), send_b(NEWHOPE_SENDBBYTES);
            std::vector<uint8_t> shared_a(32), shared_b(32);

            Botan::newhope_poly sk_a;

            keygen_timer.start();
            Botan::newhope_keygen(send_a.data(), &sk_a, nh_rng);
            keygen_timer.stop();

            sharedb_timer.start();
            Botan::newhope_sharedb(shared_b.data(), send_b.data(), send_a.data(), nh_rng);
            sharedb_timer.stop();

            shareda_timer.start();
            Botan::newhope_shareda(shared_a.data(), &sk_a, send_b.data());
            shareda_timer.stop();

            BOTAN_ASSERT(shared_a == shared_b, "Same derived key");
            }

         output() << Timer::result_string_ops(keygen_timer);
         output() << Timer::result_string_ops(shareda_timer);
         output() << Timer::result_string_ops(sharedb_timer);
         }
#endif

   };

BOTAN_REGISTER_COMMAND("speed", Speed);

}
