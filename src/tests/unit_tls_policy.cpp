/*
* TLS Policy tests
*
* (C) 2016 Juraj Somorovsky
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS)
   #include <botan/tls_policy.h>
   #include <botan/tls_exceptn.h>
#endif

#if defined(BOTAN_HAS_RSA)
   #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_ECDH)
   #include <botan/ecdh.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
   #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   #include <botan/dh.h>
#endif

#if defined(BOTAN_HAS_DSA)
   #include <botan/dsa.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_TLS)
class TLS_Policy_Unit_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_peer_key_acceptable_rsa());
         results.push_back(test_peer_key_acceptable_ecdh());
         results.push_back(test_peer_key_acceptable_ecdsa());
         results.push_back(test_peer_key_acceptable_dh());
         results.push_back(test_peer_key_acceptable_dsa());

         return results;
         }
   private:
      Test::Result test_peer_key_acceptable_rsa()
         {
         Test::Result result("TLS Policy RSA key verification");
#if defined(BOTAN_HAS_RSA)
         std::unique_ptr<Botan::Private_Key> rsa_key_1024(new Botan::RSA_PrivateKey(Test::rng(), 1024));
         Botan::TLS::Policy policy;

         try
            {
            policy.check_peer_key_acceptable(*rsa_key_1024);
            result.test_failure("Incorrectly accepting 1024 bit RSA keys");
            }
         catch(Botan::TLS::TLS_Exception&)
            {
            result.test_success("Correctly rejecting 1024 bit RSA keys");
            }

         std::unique_ptr<Botan::Private_Key> rsa_key_2048(new Botan::RSA_PrivateKey(Test::rng(), 2048));
         policy.check_peer_key_acceptable(*rsa_key_2048);
         result.test_success("Correctly accepting 2048 bit RSA keys");
#endif
         return result;
         }

      Test::Result test_peer_key_acceptable_ecdh()
         {
         Test::Result result("TLS Policy ECDH key verification");
#if defined(BOTAN_HAS_ECDH)
         Botan::EC_Group group_192("secp192r1");
         std::unique_ptr<Botan::Private_Key> ecdh_192(new Botan::ECDH_PrivateKey(Test::rng(), group_192));

         Botan::TLS::Policy policy;
         try
            {
            policy.check_peer_key_acceptable(*ecdh_192);
            result.test_failure("Incorrectly accepting 192 bit EC keys");
            }
         catch(Botan::TLS::TLS_Exception&)
            {
            result.test_success("Correctly rejecting 192 bit EC keys");
            }

         Botan::EC_Group group_256("secp256r1");
         std::unique_ptr<Botan::Private_Key> ecdh_256(new Botan::ECDH_PrivateKey(Test::rng(), group_256));
         policy.check_peer_key_acceptable(*ecdh_256);
         result.test_success("Correctly accepting 256 bit EC keys");
#endif
         return result;
         }

      Test::Result test_peer_key_acceptable_ecdsa()
         {
         Test::Result result("TLS Policy ECDSA key verification");
#if defined(BOTAN_HAS_ECDSA)
         Botan::EC_Group group_192("secp192r1");
         std::unique_ptr<Botan::Private_Key> ecdsa_192(new Botan::ECDSA_PrivateKey(Test::rng(), group_192));

         Botan::TLS::Policy policy;
         try
            {
            policy.check_peer_key_acceptable(*ecdsa_192);
            result.test_failure("Incorrectly accepting 192 bit EC keys");
            }
         catch(Botan::TLS::TLS_Exception&)
            {
            result.test_success("Correctly rejecting 192 bit EC keys");
            }

         Botan::EC_Group group_256("secp256r1");
         std::unique_ptr<Botan::Private_Key> ecdsa_256(new Botan::ECDSA_PrivateKey(Test::rng(), group_256));
         policy.check_peer_key_acceptable(*ecdsa_256);
         result.test_success("Correctly accepting 256 bit EC keys");
#endif
         return result;
         }

      Test::Result test_peer_key_acceptable_dh()
         {
         Test::Result result("TLS Policy DH key verification");
#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
         const BigInt g("2");
         const BigInt p("58458002095536094658683755258523362961421200751439456159756164191494576279467");
         const Botan::DL_Group grp(p, g);
         const Botan::BigInt x("46205663093589612668746163860870963912226379131190812163519349848291472898748");
         std::unique_ptr<Botan::Private_Key> dhkey(new Botan::DH_PrivateKey(Test::rng(), grp, x));

         Botan::TLS::Policy policy;
         try
            {
            policy.check_peer_key_acceptable(*dhkey);
            result.test_failure("Incorrectly accepting short bit DH keys");
            }
         catch(Botan::TLS::TLS_Exception&)
            {
            result.test_success("Correctly rejecting short bit DH keys");
            }
#endif
         return result;
         }

      Test::Result test_peer_key_acceptable_dsa()
         {
         Test::Result result("TLS Policy DSA key verification");
#if defined(BOTAN_HAS_DSA)
         const Botan::DL_Group grp_1024("modp/ietf/1024");
         std::unique_ptr<Botan::Private_Key> dsa_1024(new Botan::DSA_PrivateKey(Test::rng(), grp_1024));

         Botan::TLS::Policy policy;
         try
            {
            policy.check_peer_key_acceptable(*dsa_1024);
            result.test_failure("Incorrectly accepting short bit DSA keys");
            }
         catch(Botan::TLS::TLS_Exception&)
            {
            result.test_success("Correctly rejecting short bit DSA keys");
            }

         const Botan::DL_Group grp_2048("modp/ietf/2048");
         std::unique_ptr<Botan::Private_Key> dsa_2048(new Botan::DSA_PrivateKey(Test::rng(), grp_2048));
         policy.check_peer_key_acceptable(*dsa_2048);
         result.test_success("Correctly accepting 2048 bit DSA keys");
#endif
         return result;
         }


   };

BOTAN_REGISTER_TEST("tls", "tls_policy", TLS_Policy_Unit_Tests);

#endif

}

}
