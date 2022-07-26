/*
* (C) 2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ZFEC)

#include <botan/zfec.h>

namespace Botan_Tests {

class ZFEC_KAT final : public Text_Based_Test
   {
   public:
      ZFEC_KAT() : Text_Based_Test("zfec.vec", "K,N,Data,Code") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override
         {
         const size_t K = vars.get_req_sz("K");
         const size_t N = vars.get_req_sz("N");

         const std::vector<uint8_t> input    = vars.get_req_bin("Data");
         const std::vector<uint8_t> expected = vars.get_req_bin("Code");

         if(input.size() % K != 0)
            {
            throw Test_Error("ZFEC input is not a multiple of K bytes");
            }

         Test::Result result("ZFEC encoding/decoding");

         const size_t share_size = input.size() / K;

         if(expected.size() != share_size * (N - K))
            {
            throw Test_Error("ZFEC output does not coorespond with K/N");
            }

         std::map<size_t, const uint8_t*> shares;

         for(size_t i = 0; i != N; ++i)
            {
            const uint8_t* expected_share = nullptr;
            if(i < K)
               expected_share = &input[share_size*i];
            else
               expected_share = &expected[share_size*(i-K)];

            shares.insert(std::make_pair(i, expected_share));
            }

         Botan::ZFEC zfec(K, N);

         const std::string zfec_impl = zfec.provider();

         std::set<size_t> shares_encoded;

         auto zfec_enc_fn = [&](size_t share,
                                const uint8_t block[], size_t len)
            {
            if(shares_encoded.insert(share).second == false)
               {
               result.test_failure("Encoding returned the same share twice");
               }

            result.test_lt("ZFEC enc share in range", share, N);

            result.test_eq(zfec_impl.c_str(),
                           "share " + std::to_string(share),
                           block, len,
                           shares[share], share_size);
            };

         zfec.encode(input.data(), input.size(), zfec_enc_fn);

         result.test_eq("Correct number of shares encoded",
                        shares_encoded.size(), N);

         // First test full decoding:
         std::set<size_t> shares_decoded;

         auto zfec_dec_fn = [&](size_t share,
                                const uint8_t block[], size_t len)
            {
            if(shares_decoded.insert(share).second == false)
               {
               result.test_failure("Decoding returned the same share twice");
               }

            result.test_lt("ZFEC dec share in range", share, K);

            result.test_eq(zfec_impl.c_str(),
                           "share " + std::to_string(share),
                           block, len,
                           &input[share * share_size], share_size);
            };

         zfec.decode_shares(shares, share_size, zfec_dec_fn);

         result.test_eq("Correct number of shares decoded",
                        shares_decoded.size(), K);

         // And test error correction. Corrupt E<=(N-K)/2 shares by changing
         // a single byte in each. Expect to recover the original data.
         shares_decoded.clear();
         const size_t shares_to_corrupt = (N-K)/2;

         std::map<size_t, std::vector<uint8_t>> input_corrupted;
         std::map<size_t, uint8_t*> shares_corrupted;
         for(size_t i = 0; i != N; ++i)
            {
            auto elem = input_corrupted.insert(std::make_pair(i, std::vector<uint8_t>(shares[i], shares[i] + share_size))).first;
            shares_corrupted[i] = elem->second.data();
            }
         const size_t corruption_offset = rng().next_byte() % share_size;
         for(size_t i = 0; i < shares_to_corrupt; ++i)
            {
            const size_t which = rng().next_byte() % N;
            input_corrupted[which][corruption_offset] ^= 0xff;
            }

         zfec.decode_corrected(shares_corrupted, share_size, zfec_dec_fn);

         result.test_eq("Correct number of shares decoded",
                        shares_decoded.size(), K);

         // Now remove N-K-1 shares and corrupt one. correct() should be able to recognize the
         // inconsistency but not be able to resolve it.
         shares_decoded.clear();
         input_corrupted.clear();
         shares_corrupted.clear();

         for(size_t i = N-K-1; i < N; ++i)
            {
            auto elem = input_corrupted.insert(std::make_pair(i, std::vector<uint8_t>(shares[i], shares[i] + share_size))).first;
            shares_corrupted[i] = elem->second.data();
            }
         input_corrupted[N-1][0] ^= 0xAA;

         result.test_throws("too many errors", [&]() {
            zfec.correct(shares_corrupted, share_size);
            });

         // Back to the uncorrupted input. Now remove random N-K shares to get the smallest possible set:
         shares_decoded.clear();

         while(shares.size() != K)
            {
            const size_t idx = rng().next_byte();
            shares.erase(idx);
            }

         zfec.decode_shares(shares, share_size, zfec_dec_fn);

         result.test_eq("Correct number of shares decoded",
                        shares_decoded.size(), K);

         return result;
         }

   };

BOTAN_REGISTER_TEST("zfec", "zfec", ZFEC_KAT);

}

#endif
