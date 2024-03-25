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
   #include <botan/pk_algs.h>
   #include <botan/internal/fmt.h>

namespace Botan_Tests {

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
class PK_PQC_KEM_KAT_Test : public PK_Test {
   protected:
      /// Type of a KAT vector entry that can be recomputed using the seed
      enum class VarType { SharedSecret, PublicKey, PrivateKey, Ciphertext };

      PK_PQC_KEM_KAT_Test(const std::string& algo_name, const std::string& input_file) :
            PK_Test(algo_name, input_file, "Seed,SS,PK,SK,CT") {}

      // --- Callbacks ---

      /// Map a recomputed value to the expected value from the KAT vector (e.g. apply a hash function if Botan's KAT entry is hashed)
      virtual std::vector<uint8_t> map_value(const std::string& params,
                                             std::span<const uint8_t> value,
                                             VarType value_type) const = 0;

      /// Create an RNG that can be used to generate the keypair. @p rng is the DRBG that is used to expand the seed.
      virtual Fixed_Output_RNG rng_for_keygen(const std::string& params, Botan::RandomNumberGenerator& rng) const = 0;

      /// Create an RNG that can be used to generate the keypair. @p rng is the DRBG that is used to expand the seed.
      virtual Fixed_Output_RNG rng_for_encapsulation(const std::string& params,
                                                     Botan::RandomNumberGenerator& rng) const = 0;

      /// Return true if the algorithm with the specified params should be tested
      virtual bool is_available(const std::string& params) const = 0;

      /// Callback to test the RNG's state after key generation. If not overridden checks that the RNG is empty.
      virtual void inspect_rng_after_keygen(const std::string& params,
                                            const Fixed_Output_RNG& rng_keygen,
                                            Test::Result& result) const {
         BOTAN_UNUSED(params);
         result.confirm("All prepared random bits used for key generation", rng_keygen.empty());
      }

      /// Callback to test the RNG's state after encapsulation. If not overridden checks that the RNG is empty.
      virtual void inspect_rng_after_encaps(const std::string& params,
                                            const Fixed_Output_RNG& rng_encaps,
                                            Test::Result& result) const {
         BOTAN_UNUSED(params);
         result.confirm("All prepared random bits used for encapsulation", rng_encaps.empty());
      }

   private:
      bool skip_this_test(const std::string& params, const VarMap&) final {
   #if !defined(BOTAN_HAS_AES)
         BOTAN_UNUSED(params);
         return true;
   #else
         return !is_available(params);
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

      Test::Result run_one_test(const std::string& params, const VarMap& vars) final {
         Test::Result result(Botan::fmt("PQC KAT for {} with parameters {}", algo_name(), params));

         // All PQC algorithms use this DRBG in their KAT tests to generate
         // their private keys. The amount of data that needs to be pulled from
         // the RNG for keygen and encapsulation is dependent on the algorithm
         // and the implementation.
         auto ctr_drbg = create_drbg(vars.get_req_bin("Seed"));
         auto rng_keygen = rng_for_keygen(params, *ctr_drbg);
         auto rng_encaps = rng_for_encapsulation(params, *ctr_drbg);

         // Key Generation
         auto sk = Botan::create_private_key(algo_name(), rng_keygen, params);
         if(!result.test_not_null("Successfully generated private key", sk)) {
            return result;
         }
         result.test_is_eq("Generated private key",
                           map_value(params, sk->raw_private_key_bits(), VarType::PrivateKey),
                           vars.get_req_bin("SK"));
         inspect_rng_after_keygen(params, rng_keygen, result);

         // Algorithm properties
         result.test_eq("Algorithm name", sk->algo_name(), algo_name());
         result.confirm("Supported operation KeyEncapsulation",
                        sk->supports_operation(Botan::PublicKeyOperation::KeyEncapsulation));
         result.test_gte("Key has reasonable estimated strength (lower)", sk->estimated_strength(), 64);
         result.test_lt("Key has reasonable estimated strength (upper)", sk->estimated_strength(), 512);

         // Extract Public Key
         auto pk = sk->public_key();
         result.test_is_eq("Generated public key",
                           map_value(params, pk->public_key_bits(), VarType::PublicKey),
                           vars.get_req_bin("PK"));

         // Serialize/Deserialize the Public Key
         auto pk2 = Botan::load_public_key(pk->algorithm_identifier(), pk->public_key_bits());
         if(!result.test_not_null("Successfully deserialized public key", pk2)) {
            return result;
         }

         // Encapsulation
         auto enc = Botan::PK_KEM_Encryptor(*pk2, "Raw");
         const auto encaped = enc.encrypt(rng_encaps, 0 /* no KDF */);
         result.test_is_eq(
            "Shared Secret", map_value(params, encaped.shared_key(), VarType::SharedSecret), vars.get_req_bin("SS"));
         result.test_is_eq("Ciphertext",
                           map_value(params, encaped.encapsulated_shared_key(), VarType::Ciphertext),
                           vars.get_req_bin("CT"));
         inspect_rng_after_encaps(params, rng_keygen, result);

         // Decapsulation
         auto sk2 = Botan::load_private_key(sk->algorithm_identifier(), sk->private_key_bits());
         Botan::Null_RNG null_rng;
         auto dec = Botan::PK_KEM_Decryptor(*sk2, null_rng, "Raw");
         const auto shared_key = dec.decrypt(encaped.encapsulated_shared_key(), 0 /* no KDF */);
         result.test_is_eq("Decaps. Shared Secret", shared_key, Botan::lock(vars.get_req_bin("SS")));

         return result;
      }
};

}  // namespace Botan_Tests

#endif

#endif
