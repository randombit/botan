/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PBKDF)
   #include <botan/pbkdf.h>
#endif

#if defined(BOTAN_HAS_PGP_S2K)
   #include <botan/pgp_s2k.h>
#endif

#if defined(BOTAN_HAS_SCRYPT)
   #include <botan/scrypt.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_PBKDF)
class PBKDF_KAT_Tests final : public Text_Based_Test
   {
   public:
      PBKDF_KAT_Tests() : Text_Based_Test("pbkdf", "Iterations,Salt,Passphrase,Output", "OutputLen") {}

      Test::Result run_one_test(const std::string& pbkdf_name, const VarMap& vars) override
         {
         const size_t iterations = vars.get_req_sz("Iterations");
         const std::vector<uint8_t> salt = vars.get_req_bin("Salt");
         const std::string passphrase = vars.get_req_str("Passphrase");
         const std::vector<uint8_t> expected = vars.get_req_bin("Output");
         const size_t outlen = vars.get_opt_sz("OutputLen", expected.size());

         Test::Result result(pbkdf_name);
         std::unique_ptr<Botan::PBKDF> pbkdf(Botan::PBKDF::create(pbkdf_name));

         if(!pbkdf)
            {
            result.note_missing(pbkdf_name);
            return result;
            }

         result.test_eq("Expected name", pbkdf->name(), pbkdf_name);

         const Botan::secure_vector<uint8_t> derived =
            pbkdf->derive_key(outlen, passphrase, salt.data(), salt.size(), iterations).bits_of();

         result.test_eq("derived key", derived, expected);

         return result;
         }

   };

BOTAN_REGISTER_TEST("pbkdf", PBKDF_KAT_Tests);

#endif

#if defined(BOTAN_HAS_SCRYPT)

class Scrypt_KAT_Tests final : public Text_Based_Test
   {
   public:
      Scrypt_KAT_Tests() : Text_Based_Test("scrypt.vec", "Passphrase,Salt,N,R,P,Output") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         const size_t N = vars.get_req_sz("N");
         const size_t R = vars.get_req_sz("R");
         const size_t P = vars.get_req_sz("P");
         const std::vector<uint8_t> salt = vars.get_req_bin("Salt");
         const std::string passphrase = vars.get_req_str("Passphrase");
         const std::vector<uint8_t> expected = vars.get_req_bin("Output");

         Test::Result result("scrypt");

         if(N >= 1048576 && Test::run_long_tests() == false)
            return result;

         std::vector<uint8_t> output(expected.size());
         Botan::scrypt(output.data(), output.size(),
                       passphrase, salt.data(), salt.size(),
                       N, R, P);

         result.test_eq("derived key", output, expected);

         return result;
         }

   };

BOTAN_REGISTER_TEST("scrypt", Scrypt_KAT_Tests);

#endif

#if defined(BOTAN_HAS_PGP_S2K)

class PGP_S2K_Iter_Test final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("PGP_S2K iteration encoding");

         // The maximum representable iteration count
         const size_t max_iter = 65011712;

         result.test_eq("Encoding of large value accepted",
                        Botan::OpenPGP_S2K::encode_count(max_iter * 2), size_t(255));
         result.test_eq("Encoding of small value accepted",
                        Botan::OpenPGP_S2K::encode_count(0), size_t(0));

         for(size_t c = 0; c != 256; ++c)
            {
            const size_t dec = Botan::OpenPGP_S2K::decode_count(static_cast<uint8_t>(c));
            const size_t comp_dec = (16 + (c & 0x0F)) << ((c >> 4) + 6);
            result.test_eq("Decoded value matches PGP formula", dec, comp_dec);
            }

         uint8_t last_enc = 0;

         for(size_t i = 0; i <= max_iter; i += 64)
            {
            const uint8_t enc = Botan::OpenPGP_S2K::encode_count(i);
            result.test_lte("Encoded value non-decreasing", last_enc, enc);

            /*
            The iteration count as encoded may not be exactly the
            value requested, but should never be less
            */
            const size_t dec = Botan::OpenPGP_S2K::decode_count(enc);
            result.test_gte("Decoded value is >= requested", dec, i);

            last_enc = enc;
            }

         return std::vector<Test::Result>{result};
         }
   };

BOTAN_REGISTER_TEST("pgp_s2k_iter", PGP_S2K_Iter_Test);

#endif

}

}
