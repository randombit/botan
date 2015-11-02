/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEST_PUBKEY_H__
#define BOTAN_TEST_PUBKEY_H__

#include "tests.h"
#include <botan/pubkey.h>

namespace Botan_Tests {

class PK_Signature_Generation_Test : public Text_Based_Test
   {
   public:
      PK_Signature_Generation_Test(const std::string& algo,
                                                 const std::string& test_src,
                                                 const std::vector<std::string>& required_keys,
                                                 const std::vector<std::string>& optional_keys = {},
                                                 bool clear_between = true) :
         Text_Based_Test(algo, test_src, required_keys, optional_keys, clear_between) {}

      virtual std::string default_padding(const VarMap&) const
         {
         throw std::runtime_error("No default padding scheme set for " + algo_name());
         }

      virtual std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) = 0;

      Test::Result run_one_test(const std::string&, const VarMap& vars) override;
   };

class PK_Signature_Verification_Test : public Text_Based_Test
   {
   public:
      PK_Signature_Verification_Test(const std::string& algo,
                                     const std::string& test_src,
                                     const std::vector<std::string>& required_keys,
                                     const std::vector<std::string>& optional_keys = {},
                                     bool clear_between = true) :
         Text_Based_Test(algo, test_src, required_keys, optional_keys, clear_between) {}

      virtual std::string default_padding(const VarMap&) const
         {
         throw std::runtime_error("No default padding scheme set for " + algo_name());
         }

      virtual std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) = 0;

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override;
   };

class PK_Encryption_Decryption_Test : public Text_Based_Test
   {
   public:
      PK_Encryption_Decryption_Test(const std::string& algo,
                                    const std::string& test_src,
                                    const std::vector<std::string>& required_keys,
                                    const std::vector<std::string>& optional_keys = {},
                                    bool clear_between = true) :
         Text_Based_Test(algo, test_src, required_keys, optional_keys, clear_between) {}

      virtual std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) = 0;

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override;

      virtual std::string default_padding(const VarMap&) const { return "Raw"; }
};



}

using namespace Botan;

size_t validate_encryption(Botan::PK_Encryptor& e, Botan::PK_Decryptor& d,
                           const std::string& algo,
                           const std::string& input,
                           const std::string& random,
                           const std::string& expected);

size_t validate_signature(PK_Verifier& v, PK_Signer& s,
                          const std::string& algo,
                          const std::string& input,
                          RandomNumberGenerator& signer_rng,
                          RandomNumberGenerator& test_rng,
                          const std::string& exp);

size_t validate_signature(PK_Verifier& v, PK_Signer& s,
                          const std::string& algo,
                          const std::string& input,
                          RandomNumberGenerator& rng,
                          const std::string& exp);

size_t validate_signature(PK_Verifier& v, PK_Signer& s,
                          const std::string& algo,
                          const std::string& input,
                          RandomNumberGenerator& rng,
                          const std::string& random,
                          const std::string& exp);

size_t validate_kas(PK_Key_Agreement& kas,
                    const std::string& algo,
                    const std::vector<byte>& pubkey,
                    const std::string& output,
                    size_t keylen);

#endif
