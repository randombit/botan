/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "catchy/catch.hpp"
#include <botan/version.h>

#if defined(BOTAN_HAS_FFI)

#include <botan/hex.h>
#include <botan/ffi.h>

TEST_CASE("FFI versioning", "[ffi]")
   {
   CHECK(botan_ffi_api_version() == BOTAN_HAS_FFI);
   CHECK(botan_version_major() == Botan::version_major());
   CHECK(botan_version_minor() == Botan::version_minor());
   CHECK(botan_version_patch() == Botan::version_patch());
   }

TEST_CASE("FFI hex", "[ffi]")
   {
   const std::vector<uint8_t> bin = { 0xAA, 0xDE, 0x01 };
   std::string out;
   out.resize(2*bin.size());

   CHECK(botan_hex_encode(bin.data(), bin.size(), &out[0], 0) == 0);
   CHECK(out == "AADE01");

   CHECK(botan_hex_encode(bin.data(), bin.size(), &out[0], BOTAN_FFI_HEX_LOWER_CASE) == 0);
   CHECK(out == "aade01");
   }

TEST_CASE("FFI RNG", "[ffi]")
   {
   botan_rng_t rng;
   unsigned char buf[512];

   CHECK(botan_rng_init(&rng, "bad_type") < 0);

   const char* types[] = { "system", "user", nullptr };

   for(size_t i = 0; types[i]; ++i)
      {
      REQUIRE(botan_rng_init(&rng, types[i]) == 0);
      CHECK(botan_rng_get(rng, buf, sizeof(buf)) == 0);
      CHECK(botan_rng_reseed(rng, 256) == 0);
      CHECK(botan_rng_destroy(rng) == 0);
      }
   }

TEST_CASE("FFI hash", "[ffi]")
   {
   botan_hash_t hash;
   CHECK(botan_hash_init(&hash, "SHA-256", 1) < 0);
   REQUIRE(botan_hash_init(&hash, "SHA-256", 0) == 0);

   /*
   char namebuf[32];
   CHECK(botan_hash_name(hash, namebuf, 5) < 0);
   CHECK(botan_hash_name(hash, namebuf, 31) == 0);
   CHECK(std::string(namebuf) == "SHA-256");
   */

   size_t ol;
   CHECK(botan_hash_output_length(hash, &ol) == 0);
   CHECK(ol == 32);

   const char* s = "ABC";

   std::vector<uint8_t> outbuf(ol);
   CHECK(botan_hash_update(hash, reinterpret_cast<const uint8_t*>(s), 3) == 0);
   CHECK(botan_hash_final(hash, outbuf.data()) == 0);

   //CHECK_ARRAY(outbuf, "B5D4045C3F466FA91FE2CC6ABE79232A1A57CDF104F7A26E716E0A1E2789DF78");
   CHECK(Botan::hex_encode(outbuf) == "B5D4045C3F466FA91FE2CC6ABE79232A1A57CDF104F7A26E716E0A1E2789DF78");

   CHECK(botan_hash_clear(hash) == 0);

   CHECK(botan_hash_destroy(hash) == 0);
   }

TEST_CASE("FFI mac", "[ffi]")
   {
   botan_mac_t mac;
   CHECK(botan_mac_init(&mac, "HMAC(SHA-256)", 1) < 0);
   CHECK(botan_mac_init(&mac, "HMAC(SHA-256)", 0) == 0);

   //char namebuf[32];
   //CHECK(botan_mac_name(mac, namebuf, 10) < 0);
   //CHECK(botan_mac_name(mac, namebuf, 31) == 0);
   //CHECK(std::string(namebuf) == "HMAC(SHA-256)");

   size_t ol;
   CHECK(botan_mac_output_length(mac, &ol) == 0);
   CHECK(ol == 32);

   const uint8_t key[] = { 0xAA, 0xBB, 0xCC, 0xDD };

   CHECK(botan_mac_set_key(mac, key, 4) == 0);
   const char* s = "ABC";

   std::vector<uint8_t> outbuf(ol);
   CHECK(botan_mac_update(mac, reinterpret_cast<const uint8_t*>(s), 3) == 0);
   CHECK(botan_mac_final(mac, outbuf.data()) == 0);

   CHECK(Botan::hex_encode(outbuf) == "1A82EEA984BC4A7285617CC0D05F1FE1D6C96675924A81BC965EE8FF7B0697A7");

   CHECK(botan_mac_clear(mac) == 0);
   CHECK(botan_mac_destroy(mac) == 0);
   }

TEST_CASE("FFI PBKDF", "[ffi]")
   {
   const std::vector<uint8_t> salt = Botan::hex_decode("ED1F39A0A7F3889AAF7E60743B3BC1CC2C738E60");
   const std::string passphrase = "ltexmfeyylmlbrsyikaw";
   const size_t out_len = 10;
   const size_t iterations = 1000;

   std::vector<uint8_t> outbuf(out_len);

   CHECK(botan_pbkdf("PBKDF2(SHA-1)", outbuf.data(), outbuf.size(),
                     passphrase.c_str(), salt.data(), salt.size(), iterations) == 0);

   CHECK(Botan::hex_encode(outbuf) == "027AFADD48F4BE8DCC4F");

   size_t iters_10ms, iters_100ms;
   CHECK(botan_pbkdf_timed("PBKDF2(SHA-1)", outbuf.data(), outbuf.size(),
                           passphrase.c_str(), salt.data(), salt.size(), 10, &iters_10ms) == 0);
   CHECK(botan_pbkdf_timed("PBKDF2(SHA-1)", outbuf.data(), outbuf.size(),
                           passphrase.c_str(), salt.data(), salt.size(), 100, &iters_100ms) == 0);

   INFO("Iterations " << iters_10ms << " " << iters_100ms);
   const double ratio = static_cast<double>(iters_100ms) / iters_10ms;
   CHECK(ratio >= 5);
   CHECK(ratio <= 15);
   }

TEST_CASE("FFI KDF", "[ffi]")
   {
   const std::vector<uint8_t> secret = Botan::hex_decode("92167440112E");
   const std::vector<uint8_t> salt = Botan::hex_decode("45A9BEDED69163123D0348F5185F61ABFB1BF18D6AEA454F");
   const size_t out_len = 18;
   std::vector<uint8_t> out_buf(out_len);

   REQUIRE(botan_kdf("KDF2(SHA-1)", out_buf.data(), out_len,
                     secret.data(), secret.size(), salt.data(), salt.size()) == 0);

   CHECK(Botan::hex_encode(out_buf) == "3A5DC9AA1C872B4744515AC2702D6396FC2A");
   }

TEST_CASE("FFI bcrypt", "[ffi]")
   {
   std::vector<uint8_t> outbuf(62);
   size_t ol = outbuf.size();

   botan_rng_t rng;
   botan_rng_init(&rng, "system");

   CHECK(botan_bcrypt_generate(outbuf.data(), &ol, "password", rng, 10, 0) == 0);
   botan_rng_destroy(rng);

   CHECK(botan_bcrypt_is_valid("wrong", reinterpret_cast<const char*>(outbuf.data())) == 1);
   CHECK(botan_bcrypt_is_valid("password", reinterpret_cast<const char*>(outbuf.data())) == 0);

   }

#endif
