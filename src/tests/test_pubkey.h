/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEST_PUBKEY_H_
#define BOTAN_TEST_PUBKEY_H_

#include "tests.h"

#include "test_rng.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)

   #include <botan/pubkey.h>

namespace Botan_Tests {

class PK_Test : public Text_Based_Test {
   public:
      PK_Test(const std::string& algo,
              const std::string& test_src,
              const std::string& required_keys,
              const std::string& optional_keys = {}) :
            Text_Based_Test(test_src, required_keys, optional_keys), m_algo(algo) {}

      std::string algo_name() const { return m_algo; }

   protected:
      std::vector<std::string> possible_providers(const std::string& params) override;

      virtual std::string default_padding(const VarMap&) const {
         throw Test_Error("No default padding scheme set for " + algo_name());
      }

      virtual std::string printed_params(const VarMap& /*vm*/, const std::string& padding) const { return padding; }

      virtual std::string choose_padding(const VarMap& vars, const std::string& pad_hdr);

   private:
      std::string m_algo;
};

class PK_Signature_Generation_Test : public PK_Test {
   public:
      PK_Signature_Generation_Test(const std::string& algo,
                                   const std::string& test_src,
                                   const std::string& required_keys,
                                   const std::string& optional_keys = "") :
            PK_Test(algo, test_src, required_keys, optional_keys) {}

      virtual std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) = 0;

      virtual std::unique_ptr<Botan::RandomNumberGenerator> test_rng(const std::vector<uint8_t>& nonce) const {
         return std::make_unique<Fixed_Output_RNG>(nonce);
      }

   private:
      Test::Result run_one_test(const std::string&, const VarMap& vars) final;
};

class PK_Signature_Verification_Test : public PK_Test {
   public:
      PK_Signature_Verification_Test(const std::string& algo,
                                     const std::string& test_src,
                                     const std::string& required_keys,
                                     const std::string& optional_keys = "") :
            PK_Test(algo, test_src, required_keys, optional_keys) {}

      virtual Botan::Signature_Format sig_format() const;

      virtual bool test_random_invalid_sigs() const { return true; }

      virtual std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) = 0;

   private:
      Test::Result run_one_test(const std::string& header, const VarMap& vars) final;
};

class PK_Signature_NonVerification_Test : public PK_Test {
   public:
      PK_Signature_NonVerification_Test(const std::string& algo,
                                        const std::string& test_src,
                                        const std::string& required_keys,
                                        const std::string& optional_keys = "") :
            PK_Test(algo, test_src, required_keys, optional_keys) {}

      bool clear_between_callbacks() const override { return false; }

      virtual std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) = 0;

   private:
      Test::Result run_one_test(const std::string& header, const VarMap& vars) final;
};

class PK_Sign_Verify_DER_Test : public Test {
   public:
      PK_Sign_Verify_DER_Test(const std::string& algo, const std::string& padding) : m_algo(algo), m_padding(padding) {}

      std::string algo_name() const { return m_algo; }

   protected:
      std::vector<Test::Result> run() final;

      virtual std::unique_ptr<Botan::Private_Key> key() = 0;

      virtual bool test_random_invalid_sigs() const { return true; }

      std::vector<std::string> possible_providers(const std::string& params) override;

   private:
      std::string m_algo;
      std::string m_padding;
};

class PK_Encryption_Decryption_Test : public PK_Test {
   public:
      PK_Encryption_Decryption_Test(const std::string& algo,
                                    const std::string& test_src,
                                    const std::string& required_keys,
                                    const std::string& optional_keys = "") :
            PK_Test(algo, test_src, required_keys, optional_keys) {}

      virtual std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) = 0;

      std::string default_padding(const VarMap&) const override { return "Raw"; }

      virtual std::unique_ptr<Botan::RandomNumberGenerator> test_rng(const std::vector<uint8_t>& nonce) const {
         return std::make_unique<Fixed_Output_RNG>(nonce);
      }

   private:
      Test::Result run_one_test(const std::string& header, const VarMap& vars) final;
};

class PK_Decryption_Test : public PK_Test {
   public:
      PK_Decryption_Test(const std::string& algo,
                         const std::string& test_src,
                         const std::string& required_keys,
                         const std::string& optional_keys = "") :
            PK_Test(algo, test_src, required_keys, optional_keys) {}

      virtual std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) = 0;

      std::string default_padding(const VarMap&) const override { return "Raw"; }

   private:
      Test::Result run_one_test(const std::string& header, const VarMap& vars) final;
};

class PK_Key_Agreement_Test : public PK_Test {
   public:
      PK_Key_Agreement_Test(const std::string& algo,
                            const std::string& test_src,
                            const std::string& required_keys,
                            const std::string& optional_keys = "") :
            PK_Test(algo, test_src, required_keys, optional_keys) {}

      virtual bool agreement_should_fail(const std::string& header, const VarMap& vars) const {
         BOTAN_UNUSED(header, vars);
         return false;
      }

      virtual std::unique_ptr<Botan::Private_Key> load_our_key(const std::string& header, const VarMap& vars) = 0;

      virtual std::vector<uint8_t> load_their_key(const std::string& header, const VarMap& vars) = 0;

      virtual std::string default_kdf(const VarMap&) const { return "Raw"; }

   private:
      Test::Result run_one_test(const std::string& header, const VarMap& vars) final;
};

class PK_KEM_Test : public PK_Test {
   public:
      PK_KEM_Test(const std::string& algo,
                  const std::string& test_src,
                  const std::string& required_keys,
                  const std::string& optional_keys = "") :
            PK_Test(algo, test_src, required_keys, optional_keys) {}

      virtual std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) = 0;

   private:
      Test::Result run_one_test(const std::string& header, const VarMap& vars) final;
};

class PK_Key_Generation_Test : public Test {
   protected:
      std::vector<Test::Result> run() final;

      virtual std::vector<std::string> keygen_params() const = 0;

      virtual std::string algo_name(std::string_view param) const {
         BOTAN_UNUSED(param);
         return algo_name();
      }

      virtual std::string algo_name() const = 0;

      /**
       * Algorithm-specific decoding of raw key bits returned from
       * `Public_Key::raw_public_key_bits()`. If an algorithm does not support reading
       * the raw key bits, this method should return nullptr.
       */
      virtual std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view keygen_params,
                                                                     std::string_view provider,
                                                                     std::span<const uint8_t> raw_key_bits) const = 0;

      std::vector<std::string> possible_providers(const std::string& params) override;
};

class PK_Key_Generation_Stability_Test : public PK_Test {
   public:
      PK_Key_Generation_Stability_Test(const std::string& algo, const std::string& test_src);

      Test::Result run_one_test(const std::string& header, const VarMap& vars) final;

      bool clear_between_callbacks() const override { return false; }
};

class PK_Key_Validity_Test : public PK_Test {
   protected:
      PK_Key_Validity_Test(const std::string& algo,
                           const std::string& test_src,
                           const std::string& required_keys,
                           const std::string& optional_keys = "") :
            PK_Test(algo, test_src, required_keys, optional_keys) {}

      virtual std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) = 0;

   private:
      Test::Result run_one_test(const std::string& header, const VarMap& vars) final;
};

void check_invalid_ciphertexts(Test::Result& result,
                               Botan::PK_Decryptor& decryptor,
                               const std::vector<uint8_t>& plaintext,
                               const std::vector<uint8_t>& ciphertext,
                               Botan::RandomNumberGenerator& rng);

}  // namespace Botan_Tests

#endif

#endif
