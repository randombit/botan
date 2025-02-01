/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "perf.h"
#include <set>

#if defined(BOTAN_HAS_BLOCK_CIPHER)
   #include <botan/block_cipher.h>
#endif

#if defined(BOTAN_HAS_CIPHER_MODES)
   #include <botan/cipher_mode.h>
#endif

#if defined(BOTAN_HAS_STREAM_CIPHER)
   #include <botan/stream_cipher.h>
#endif

#if defined(BOTAN_HAS_HASH)
   #include <botan/hash.h>
#endif

#if defined(BOTAN_HAS_MAC)
   #include <botan/mac.h>
#endif

#if defined(BOTAN_HAS_XOF)
   #include <botan/xof.h>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_BLOCK_CIPHER)
class PerfTest_BlockCipher final : public PerfTest {
   public:
      PerfTest_BlockCipher(std::string_view alg) : m_alg(alg) {}

      void go(const PerfConfig& config) override {
         for(const auto& provider : Botan::BlockCipher::providers(m_alg)) {
            if(auto cipher = Botan::BlockCipher::create(m_alg, provider)) {
               bench_stream_cipher(config, *cipher);
            }
         }
      }

      static bool has_impl_for(std::string_view alg) { return !Botan::BlockCipher::providers(alg).empty(); }

   private:
      void bench_stream_cipher(const PerfConfig& config, Botan::BlockCipher& cipher) {
         auto& rng = config.rng();
         const auto runtime = config.runtime();
         const auto provider = cipher.provider();

         auto ks_timer = config.make_timer(cipher.name(), 1, "key schedule", provider);

         const Botan::SymmetricKey key(rng, cipher.maximum_keylength());
         ks_timer->run([&]() { cipher.set_key(key); });

         const size_t bs = cipher.block_size();
         std::set<size_t> buf_sizes_in_blocks;
         for(size_t buf_size : config.buffer_sizes()) {
            if(buf_size % bs == 0) {
               buf_sizes_in_blocks.insert(buf_size);
            } else {
               buf_sizes_in_blocks.insert(buf_size + bs - (buf_size % bs));
            }
         }

         for(size_t buf_size : buf_sizes_in_blocks) {
            std::vector<uint8_t> buffer(buf_size);
            const size_t mult = std::max<size_t>(1, 65536 / buf_size);
            const size_t blocks = buf_size / bs;

            auto encrypt_timer = config.make_timer(cipher.name(), mult * buffer.size(), "encrypt", provider, buf_size);
            auto decrypt_timer = config.make_timer(cipher.name(), mult * buffer.size(), "decrypt", provider, buf_size);

            encrypt_timer->run_until_elapsed(runtime, [&]() {
               for(size_t i = 0; i != mult; ++i) {
                  cipher.encrypt_n(&buffer[0], &buffer[0], blocks);
               }
            });
            config.record_result(*encrypt_timer);

            decrypt_timer->run_until_elapsed(runtime, [&]() {
               for(size_t i = 0; i != mult; ++i) {
                  cipher.decrypt_n(&buffer[0], &buffer[0], blocks);
               }
            });
            config.record_result(*decrypt_timer);
         }
      }

      std::string m_alg;
};
#endif

#if defined(BOTAN_HAS_CIPHER_MODES)
class PerfTest_CipherMode final : public PerfTest {
   public:
      PerfTest_CipherMode(std::string_view alg) : m_alg(alg) {}

      void go(const PerfConfig& config) override {
         for(const auto& provider : Botan::Cipher_Mode::providers(m_alg)) {
            if(auto enc = Botan::Cipher_Mode::create(m_alg, Botan::Cipher_Dir::Encryption, provider)) {
               auto dec = Botan::Cipher_Mode::create_or_throw(m_alg, Botan::Cipher_Dir::Decryption, provider);
               bench_cipher_mode(config, *enc, *dec);
            }
         }
      }

      static bool has_impl_for(std::string_view alg) { return !Botan::Cipher_Mode::providers(alg).empty(); }

   private:
      void bench_cipher_mode(const PerfConfig& config, Botan::Cipher_Mode& enc, Botan::Cipher_Mode& dec) {
         auto& rng = config.rng();
         const auto runtime = config.runtime();
         const auto provider = enc.provider();

         auto ks_timer = config.make_timer(enc.name(), 1, "key schedule", provider);

         const Botan::SymmetricKey key(config.rng(), enc.key_spec().maximum_keylength());

         ks_timer->run([&]() { enc.set_key(key); });
         ks_timer->run([&]() { dec.set_key(key); });

         config.record_result(*ks_timer);

         for(auto buf_size : config.buffer_sizes()) {
            Botan::secure_vector<uint8_t> buffer = rng.random_vec(buf_size);
            const size_t mult = std::max<size_t>(1, 65536 / buf_size);

            auto encrypt_timer = config.make_timer(enc.name(), mult * buffer.size(), "encrypt", provider, buf_size);
            auto decrypt_timer = config.make_timer(dec.name(), mult * buffer.size(), "decrypt", provider, buf_size);

            Botan::secure_vector<uint8_t> iv = rng.random_vec(enc.default_nonce_length());

            if(buf_size >= enc.minimum_final_size()) {
               encrypt_timer->run_until_elapsed(runtime, [&]() {
                  for(size_t i = 0; i != mult; ++i) {
                     enc.start(iv);
                     enc.finish(buffer);
                     buffer.resize(buf_size);  // remove any tag or padding
                  }
               });

               while(decrypt_timer->under(runtime)) {
                  if(!iv.empty()) {
                     iv[iv.size() - 1] += 1;
                  }

                  // Create a valid ciphertext/tag for decryption to run on
                  buffer.resize(buf_size);
                  enc.start(iv);
                  enc.finish(buffer);

                  Botan::secure_vector<uint8_t> dbuffer;

                  decrypt_timer->run([&]() {
                     for(size_t i = 0; i != mult; ++i) {
                        dbuffer = buffer;
                        dec.start(iv);
                        dec.finish(dbuffer);
                     }
                  });
               }
            }

            config.record_result(*encrypt_timer);
            config.record_result(*decrypt_timer);
         }
      }

      std::string m_alg;
};
#endif

#if defined(BOTAN_HAS_STREAM_CIPHER)
class PerfTest_StreamCipher final : public PerfTest {
   public:
      PerfTest_StreamCipher(std::string_view alg) : m_alg(alg) {}

      void go(const PerfConfig& config) override {
         for(const auto& provider : Botan::StreamCipher::providers(m_alg)) {
            if(auto cipher = Botan::StreamCipher::create(m_alg, provider)) {
               bench_stream_cipher(config, *cipher);
            }
         }
      }

      static bool has_impl_for(std::string_view alg) { return !Botan::StreamCipher::providers(alg).empty(); }

   private:
      void bench_stream_cipher(const PerfConfig& config, Botan::StreamCipher& cipher) {
         auto& rng = config.rng();
         const auto runtime = config.runtime();
         const auto provider = cipher.provider();

         for(auto buf_size : config.buffer_sizes()) {
            const Botan::SymmetricKey key(rng, cipher.maximum_keylength());
            cipher.set_key(key);

            if(cipher.valid_iv_length(12)) {
               const Botan::InitializationVector iv(rng, 12);
               cipher.set_iv(iv.begin(), iv.size());
            }

            auto buffer = rng.random_vec(buf_size);

            const size_t mult = std::max<size_t>(1, 65536 / buf_size);

            auto encrypt_timer = config.make_timer(cipher.name(), mult * buffer.size(), "encrypt", provider, buf_size);

            encrypt_timer->run_until_elapsed(runtime, [&]() {
               for(size_t i = 0; i != mult; ++i) {
                  cipher.encipher(buffer);
               }
            });

            config.record_result(*encrypt_timer);

            auto ks_timer =
               config.make_timer(cipher.name(), mult * buffer.size(), "write_keystream", provider, buf_size);

            while(ks_timer->under(runtime)) {
               ks_timer->run([&]() {
                  for(size_t i = 0; i != mult; ++i) {
                     cipher.write_keystream(buffer.data(), buffer.size());
                  }
               });
            }

            config.record_result(*ks_timer);
         }
      }

      std::string m_alg;
};
#endif

#if defined(BOTAN_HAS_HASH)
class PerfTest_HashFunction final : public PerfTest {
   public:
      PerfTest_HashFunction(std::string_view alg) : m_alg(alg) {}

      void go(const PerfConfig& config) override {
         for(const auto& provider : Botan::HashFunction::providers(m_alg)) {
            if(auto hash = Botan::HashFunction::create(m_alg, provider)) {
               bench_hash_fn(config, *hash);
            }
         }
      }

      static bool has_impl_for(std::string_view alg) { return !Botan::HashFunction::providers(alg).empty(); }

   private:
      void bench_hash_fn(const PerfConfig& config, Botan::HashFunction& hash) {
         std::vector<uint8_t> output(hash.output_length());
         const auto provider = hash.provider();
         const auto runtime = config.runtime();

         for(auto buf_size : config.buffer_sizes()) {
            const auto buffer = config.rng().random_vec(buf_size);

            const size_t mult = std::max<size_t>(1, 65536 / buf_size);

            auto timer = config.make_timer(hash.name(), mult * buffer.size(), "hash", provider, buf_size);
            timer->run_until_elapsed(runtime, [&]() {
               for(size_t i = 0; i != mult; ++i) {
                  hash.update(buffer);
                  hash.final(output.data());
               }
            });
            config.record_result(*timer);
         }
      }

      std::string m_alg;
};
#endif

#if defined(BOTAN_HAS_MAC)
class PerfTest_MessageAuthenticationCode final : public PerfTest {
   public:
      PerfTest_MessageAuthenticationCode(std::string_view alg) : m_alg(alg) {}

      void go(const PerfConfig& config) override {
         for(const auto& provider : Botan::MessageAuthenticationCode::providers(m_alg)) {
            if(auto mac = Botan::MessageAuthenticationCode::create(m_alg, provider)) {
               bench_mac_fn(config, *mac);
            }
         }
      }

      static bool has_impl_for(std::string_view alg) {
         return !Botan::MessageAuthenticationCode::providers(alg).empty();
      }

   private:
      void bench_mac_fn(const PerfConfig& config, Botan::MessageAuthenticationCode& mac) {
         std::vector<uint8_t> output(mac.output_length());
         const auto provider = mac.provider();
         const auto runtime = config.runtime();
         auto& rng = config.rng();

         for(auto buf_size : config.buffer_sizes()) {
            Botan::secure_vector<uint8_t> buffer = rng.random_vec(buf_size);
            const size_t mult = std::max<size_t>(1, 65536 / buf_size);

            const Botan::SymmetricKey key(rng, mac.maximum_keylength());
            mac.set_key(key);

            auto timer = config.make_timer(mac.name(), mult * buffer.size(), "mac", provider, buf_size);
            timer->run_until_elapsed(runtime, [&]() {
               for(size_t i = 0; i != mult; ++i) {
                  if(mac.fresh_key_required_per_message()) {
                     mac.set_key(key);
                  }
                  mac.start(nullptr, 0);
                  mac.update(buffer);
                  mac.final(output.data());
               }
            });

            config.record_result(*timer);
         }
      }

      std::string m_alg;
};
#endif

#if defined(BOTAN_HAS_XOF)
class PerfTest_XOF final : public PerfTest {
   public:
      PerfTest_XOF(std::string_view alg) : m_alg(alg) {}

      void go(const PerfConfig& config) override {
         for(const auto& provider : Botan::XOF::providers(m_alg)) {
            if(auto xof = Botan::XOF::create(m_alg, provider)) {
               bench_xof_fn(config, *xof);
            }
         }
      }

      static bool has_impl_for(std::string_view alg) { return !Botan::XOF::providers(alg).empty(); }

   private:
      void bench_xof_fn(const PerfConfig& config, Botan::XOF& xof) {
         const auto runtime = config.runtime();
         const auto provider = xof.provider();

         for(size_t buf_size : config.buffer_sizes()) {
            auto in = config.rng().random_vec(buf_size);
            Botan::secure_vector<uint8_t> out(buf_size);

            auto in_timer = config.make_timer(xof.name(), in.size(), "input", provider, buf_size);
            in_timer->run_until_elapsed(runtime / 2, [&]() { xof.update(in); });

            auto out_timer = config.make_timer(xof.name(), out.size(), "output", provider, buf_size);
            out_timer->run_until_elapsed(runtime / 2, [&] { xof.output(out); });

            config.record_result(*in_timer);
            config.record_result(*out_timer);
         }
      }

      std::string m_alg;
};
#endif

//static
std::unique_ptr<PerfTest> PerfTest::get_sym(const std::string& alg) {
#if defined(BOTAN_HAS_XOF)
   if(PerfTest_XOF::has_impl_for(alg)) {
      return std::make_unique<PerfTest_XOF>(alg);
   }
#endif

#if defined(BOTAN_HAS_STREAM_CIPHER)
   if(PerfTest_StreamCipher::has_impl_for(alg)) {
      return std::make_unique<PerfTest_StreamCipher>(alg);
   }
#endif

#if defined(BOTAN_HAS_BLOCK_CIPHER)
   if(PerfTest_BlockCipher::has_impl_for(alg)) {
      return std::make_unique<PerfTest_BlockCipher>(alg);
   }
#endif

#if defined(BOTAN_HAS_CIPHER_MODES)
   if(PerfTest_CipherMode::has_impl_for(alg)) {
      return std::make_unique<PerfTest_CipherMode>(alg);
   }
#endif

#if defined(BOTAN_HAS_HASH)
   if(PerfTest_HashFunction::has_impl_for(alg)) {
      return std::make_unique<PerfTest_HashFunction>(alg);
   }
#endif

#if defined(BOTAN_HAS_MAC)
   if(PerfTest_MessageAuthenticationCode::has_impl_for(alg)) {
      return std::make_unique<PerfTest_MessageAuthenticationCode>(alg);
   }
#endif

   BOTAN_UNUSED(alg);
   return {};
}

}  // namespace Botan_CLI
