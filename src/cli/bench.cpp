/*
* (C) 2009,2010,2014,2015 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"
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
               m_time_used += (now - m_timer_start);

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
            Timer_Scope(Timer& timer) : m_timer(timer) { m_timer.start(); }
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

      uint64_t value() { stop(); return m_time_used; }
      double seconds() { return milliseconds() / 1000.0; }
      double milliseconds() { return value() / 1000000.0; }

      double ms_per_event() { return milliseconds() / events(); }
      double seconds_per_event() { return seconds() / events(); }

      uint64_t event_mult() const { return m_event_mult; }
      uint64_t events() const { return m_event_count * m_event_mult; }
      std::string get_name() const { return m_name; }
      std::string doing() const { return m_doing.empty() ? m_doing : " " + m_doing; }
   private:
      std::string m_name, m_doing;
      uint64_t m_time_used = 0, m_timer_start = 0;
      uint64_t m_event_count = 0, m_event_mult = 0;
   };

std::ostream& operator<<(std::ostream& out, Timer& timer)
   {
   const double events_per_second = timer.events() / timer.seconds();

   // use ostringstream to avoid messing with flags on the ostream& itself

   std::ostringstream oss;

   if(timer.event_mult() % 1024 == 0)
      {
      // assumed to be a byte count
      const size_t MiB = 1024*1024;

      const double MiB_total = static_cast<double>(timer.events()) / MiB;
      const double MiB_per_sec = MiB_total / timer.seconds();

      oss << timer.get_name() << timer.doing() << " "
          << std::fixed << std::setprecision(3) << MiB_per_sec << " MiB/sec"
          << " (" << MiB_total << " MiB in " << timer.milliseconds() << " ms)\n";
      }
   else
      {
      // general event counter
      oss << timer.get_name() << " "
          << static_cast<uint64_t>(events_per_second)
          << timer.doing() << "/sec; "
          << std::setprecision(2) << std::fixed
          << timer.ms_per_event() << " ms/op"
          << " (" << timer.events() << " " << (timer.events() == 1 ? "op" : "ops")
          << " in " << timer.milliseconds() << " ms)\n";
      }

   out << oss.str();
   return out;
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
      "Curve25519",
      "McEliece",
      };
   }

}

class Benchmark : public Command
   {
   public:
      Benchmark() : Command("bench --msec=1000 --provider= --buf-size=8 *algos") {}

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
                  std::bind(&Benchmark::bench_block_cipher, this, _1, _2, _3, _4));
               }
            else if(Botan::StreamCipher::providers(algo).size() > 0)
               {
               bench_providers_of<Botan::StreamCipher>(
                  algo, provider, msec, buf_size,
                  std::bind(&Benchmark::bench_stream_cipher, this, _1, _2, _3, _4));
               }
            else if(Botan::HashFunction::providers(algo).size() > 0)
               {
               bench_providers_of<Botan::HashFunction>(
                  algo, provider, msec, buf_size,
                  std::bind(&Benchmark::bench_hash, this, _1, _2, _3, _4));
               }
            else if(Botan::MessageAuthenticationCode::providers(algo).size() > 0)
               {
               bench_providers_of<Botan::MessageAuthenticationCode>(
                  algo, provider, msec, buf_size,
                  std::bind(&Benchmark::bench_mac, this, _1, _2, _3, _4));
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

#if defined(BOTAN_HAS_NUMBERTHEORY)
            else if(algo == "random_prime")
               {
               bench_random_prime(msec);
               }
#endif
            else
               {
               if(verbose() || !using_defaults)
                  {
                  error_output() << "Unknown algorithm to benchmark '" << algo << "'\n";
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
                              const std::chrono::milliseconds runtime,
                              size_t buf_size)
         {
         Botan::secure_vector<uint8_t> buffer = rng().random_vec(buf_size * 1024);

         Timer encrypt_timer(cipher.name(), provider, "encrypt", buffer.size());
         Timer decrypt_timer(cipher.name(), provider, "decrypt", buffer.size());

         while(encrypt_timer.under(runtime) && decrypt_timer.under(runtime))
            {
            const Botan::SymmetricKey key(rng(), cipher.maximum_keylength());

            cipher.set_key(key);
            encrypt_timer.run([&] { cipher.encrypt(buffer); });
            decrypt_timer.run([&] { cipher.decrypt(buffer); });
            }

         output() << encrypt_timer << decrypt_timer;
         }

      void bench_stream_cipher(Botan::StreamCipher& cipher,
                               const std::string& provider,
                               const std::chrono::milliseconds runtime,
                               size_t buf_size)
         {
         Botan::secure_vector<uint8_t> buffer = rng().random_vec(buf_size * 1024);

         Timer encrypt_timer(cipher.name(), provider, "encrypt", buffer.size());

         while(encrypt_timer.under(runtime))
            {
            const Botan::SymmetricKey key(rng(), cipher.maximum_keylength());
            cipher.set_key(key);
            encrypt_timer.run([&] { cipher.encipher(buffer); });
            }

         output() << encrypt_timer;
         }

      void bench_hash(Botan::HashFunction& hash,
                      const std::string& provider,
                      const std::chrono::milliseconds runtime,
                      size_t buf_size)
         {
         Botan::secure_vector<uint8_t> buffer = rng().random_vec(buf_size * 1024);

         Timer timer(hash.name(), provider, "hashing", buffer.size());

         while(timer.under(runtime))
            {
            timer.run([&] { hash.update(buffer); });
            }

         output() << timer;
         }

      void bench_mac(Botan::MessageAuthenticationCode& mac,
                     const std::string& provider,
                     const std::chrono::milliseconds runtime,
                     size_t buf_size)
         {
         Botan::secure_vector<uint8_t> buffer = rng().random_vec(buf_size * 1024);

         Timer timer(mac.name(), provider, "processing", buffer.size());

         while(timer.under(runtime))
            {
            const Botan::SymmetricKey key(rng(), mac.maximum_keylength());
            mac.set_key(key);
            timer.run([&] { mac.update(buffer); });
            }

         output() << timer;
         }

      void bench_cipher_mode(Botan::Cipher_Mode& enc,
                             Botan::Cipher_Mode& dec,
                             const std::chrono::milliseconds runtime,
                             size_t buf_size)
         {
         Botan::secure_vector<uint8_t> buffer = rng().random_vec(buf_size * 1024);

         Timer encrypt_timer(enc.name(), "", "encrypt", buffer.size());
         Timer decrypt_timer(enc.name(), "", "decrypt", buffer.size());

         while(encrypt_timer.under(runtime) && decrypt_timer.under(runtime))
            {
            const Botan::SymmetricKey key(rng(), enc.key_spec().maximum_keylength());
            const Botan::secure_vector<uint8_t> iv = rng().random_vec(enc.default_nonce_length());

            enc.set_key(key);
            dec.set_key(key);

            enc.start(iv);
            dec.start(iv);

            // Must run in this order, or AEADs will reject the ciphertext
            encrypt_timer.run([&] { enc.finish(buffer); });
            decrypt_timer.run([&] { dec.finish(buffer); });
            }

         output() << encrypt_timer << decrypt_timer;
         }

#if defined(BOTAN_HAS_NUMBERTHEORY)
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

            output() << genprime_timer << is_prime_timer;
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

         Botan::PK_Encryptor_EME enc(key, padding, provider);
         Botan::PK_Decryptor_EME dec(key, padding, provider);

         Timer enc_timer(nm, provider, "encrypt");
         Timer dec_timer(nm, provider, "decrypt");

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

         output() << enc_timer;
         output() << dec_timer;
         }

      void bench_pk_ka(const Botan::PK_Key_Agreement_Key& key1,
                       const Botan::PK_Key_Agreement_Key& key2,
                       const std::string& nm,
                       const std::string& provider,
                       const std::string& kdf,
                       std::chrono::milliseconds msec)
         {
         Botan::PK_Key_Agreement ka1(key1, kdf, provider);
         Botan::PK_Key_Agreement ka2(key2, kdf, provider);

         const std::vector<uint8_t> ka1_pub = key1.public_value();
         const std::vector<uint8_t> ka2_pub = key2.public_value();

         Timer ka_timer(nm, provider, "key agreements");

         while(ka_timer.under(msec))
            {
            Botan::SymmetricKey key1 = ka_timer.run([&] { return ka1.derive_key(32, ka2_pub); });
            Botan::SymmetricKey key2 = ka_timer.run([&] { return ka2.derive_key(32, ka1_pub); });

            if(key1 != key2)
               {
               error_output() << "Key agreement mismatch in PK bench\n";
               }
            }

         output() << ka_timer;
         }

      void bench_pk_sig(const Botan::Private_Key& key,
                        const std::string& nm,
                        const std::string& provider,
                        const std::string& padding,
                        std::chrono::milliseconds msec)
         {
         std::vector<uint8_t> message, signature, bad_signature;

         Botan::PK_Signer   sig(key, padding, Botan::IEEE_1363, provider);
         Botan::PK_Verifier ver(key, padding, Botan::IEEE_1363, provider);

         Timer sig_timer(nm, provider, "sign");
         Timer ver_timer(nm, provider, "verify");

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

         output() << sig_timer;
         output() << ver_timer;
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

            output() << keygen_timer;

            // Using PKCS #1 padding so OpenSSL provider can play along
            bench_pk_enc(*key, nm, provider, "EME-PKCS1-v1_5", msec);
            bench_pk_sig(*key, nm, provider, "EMSA-PKCS1-v1_5(SHA-1)", msec);
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
               return new Botan::ECDSA_PrivateKey(rng(), grp);
               }));

            output() << keygen_timer;
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
               return new Botan::DH_PrivateKey(rng(), grp);
               }));
            std::unique_ptr<Botan::PK_Key_Agreement_Key> key2(keygen_timer.run([&] {
               return new Botan::DH_PrivateKey(rng(), grp);
               }));

            output() << keygen_timer;

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
               return new Botan::ECDH_PrivateKey(rng(), grp);
               }));
            std::unique_ptr<Botan::PK_Key_Agreement_Key> key2(keygen_timer.run([&] {
               return new Botan::ECDH_PrivateKey(rng(), grp);
               }));

            output() << keygen_timer;

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

         output() << keygen_timer;

         bench_pk_ka(*key1, *key2, nm, provider, "KDF2(SHA-256)", msec);
         }
#endif


   };

BOTAN_REGISTER_COMMAND("bench", Benchmark);

}
