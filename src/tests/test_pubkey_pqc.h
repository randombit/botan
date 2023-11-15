/*
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_TEST_PUBKEY_PQC_H_
#define BOTAN_TEST_PUBKEY_PQC_H_

#include "test_pubkey.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)

   #include "test_rng.h"

   #include <botan/hash.h>
   #include <botan/internal/fmt.h>

namespace Botan_Tests {

namespace detail {

template <typename T>
concept PQC_KEM_KAT_Test_Implementation =
   std::derived_from<typename T::private_key_t, Botan::Private_Key> &&
   std::derived_from<typename T::public_key_t, Botan::Public_Key> &&
   std::convertible_to<decltype(T::input_file), std::string> &&
   std::convertible_to<decltype(T::algo_name), std::string> &&
   requires(
      T impl, Botan::RandomNumberGenerator& rng, std::span<const uint8_t> crypto_artefact, std::string_view algo_spec) {
      { T(algo_spec) } -> std::same_as<T>;
      { impl.rng_for_keygen(rng) } -> std::same_as<Botan_Tests::Fixed_Output_RNG>;
      { impl.rng_for_encapsulation(rng) } -> std::same_as<Botan_Tests::Fixed_Output_RNG>;
      { impl.map_value(crypto_artefact) } -> std::same_as<std::vector<uint8_t>>;
      { impl.available() } -> std::convertible_to<bool>;
      { std::is_constructible_v<typename T::private_key_t, Botan::RandomNumberGenerator&, decltype(impl.mode())> };
   };

}

/**
 * This is an abstraction over the Known Answer Tests used by the KEM candidates
 * in the NIST PQC competition.
 *
 * All these tests use a DRBG based on AES-256/CTR to expand seed values defined
 * in the KAT vector as entropy input for key generation and encapsulation.
 * Note that these tests won't run when the library is configured without AES.
 *
 * See also: https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/example-files
 */
template <detail::PQC_KEM_KAT_Test_Implementation Delegate>
class PK_PQC_KEM_KAT_Test : public PK_Test {
   public:
      PK_PQC_KEM_KAT_Test() : PK_Test(Delegate::algo_name, Delegate::input_file, "Seed,SS,PK,SK,CT") {}

   private:
      using Private_Key = typename Delegate::private_key_t;
      using Public_Key = typename Delegate::public_key_t;

   private:
      bool skip_this_test(const std::string& header, const VarMap&) override {
   #if !defined(BOTAN_HAS_AES)
         BOTAN_UNUSED(header);
         return true;
   #else
         return !Delegate(header).available();
   #endif
      }

      std::unique_ptr<Botan::RandomNumberGenerator> create_drbg(std::span<const uint8_t> seed) {
   #if defined(BOTAN_HAS_AES)
         return std::make_unique<CTR_DRBG_AES256>(seed);
   #else
         BOTAN_UNUSED(seed);
         throw Botan_Tests::Test_Error("PQC KAT tests require a build with AES");
   #endif
      }

      Test::Result run_one_test(const std::string& header, const VarMap& vars) final {
         Test::Result result(Botan::fmt("PQC KAT for {} with parameters {}", algo_name(), header));
         auto d = Delegate(header);

         // All PQC algorithms use this DRBG in their KAT tests to generate
         // their private keys. The amount of data that needs to be pulled from
         // the RNG for keygen and encapsulation is dependent on the algorithm
         // and the implementation.
         auto ctr_drbg = create_drbg(vars.get_req_bin("Seed"));
         auto rng_keygen = d.rng_for_keygen(*ctr_drbg);
         auto rng_encaps = d.rng_for_encapsulation(*ctr_drbg);

         // Key Generation
         auto sk = Private_Key(rng_keygen, d.mode());
         result.test_is_eq("Generated private key", d.map_value(sk.raw_private_key_bits()), vars.get_req_bin("SK"));
         result.confirm("All prepared random bits used for key generation", rng_keygen.empty());

         // Algorithm properties
         result.test_eq("algorithm name", sk.algo_name(), algo_name());
         result.confirm("supported operation", sk.supports_operation(Botan::PublicKeyOperation::KeyEncapsulation));
         result.test_gte("Key has reasonable estimated strength (lower)", sk.estimated_strength(), 64);
         result.test_lt("Key has reasonable estimated strength (upper)", sk.estimated_strength(), 512);

         // Extract Public Key
         auto pk = sk.public_key();
         result.test_is_eq("Generated public key", d.map_value(pk->public_key_bits()), vars.get_req_bin("PK"));

         // Serialize/Deserialize the Public Key
         auto pk2 = Public_Key(pk->public_key_bits(), d.mode());

         // Encapsulation
         auto enc = Botan::PK_KEM_Encryptor(pk2, "Raw");
         const auto encaped = enc.encrypt(rng_encaps, 0 /* no KDF */);
         result.test_is_eq("Shared Secret", encaped.shared_key(), Botan::lock(vars.get_req_bin("SS")));
         result.test_is_eq("Ciphertext", d.map_value(encaped.encapsulated_shared_key()), vars.get_req_bin("CT"));
         result.confirm("All prepared random bits used for encapsulation", rng_encaps.empty());

         // Decapsulation
         Private_Key sk2(sk.private_key_bits(), d.mode());
         Botan::Null_RNG null_rng;
         auto dec = Botan::PK_KEM_Decryptor(sk2, null_rng, "Raw");
         const auto shared_key = dec.decrypt(encaped.encapsulated_shared_key(), 0 /* no KDF */);
         result.test_is_eq("Decaps. Shared Secret", shared_key, Botan::lock(vars.get_req_bin("SS")));

         return result;
      }
};

}  // namespace Botan_Tests

#endif

#endif
