/*
* (C) 2019 Nuno Goncalves <nunojpg@gmail.com>
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <cassert>

#include "test_rng.h"

#if defined(BOTAN_HAS_BIGINT)
   #include <botan/bigint.h>
#endif

#if defined(BOTAN_HAS_ROUGHTIME)
   #include <botan/base64.h>
   #include <botan/ed25519.h>
   #include <botan/hex.h>
   #include <botan/roughtime.h>
#endif
namespace Botan_Tests {

#if defined(BOTAN_HAS_ROUGHTIME)

class Roughtime_Request_Tests final : public Text_Based_Test
   {
   public:
      Roughtime_Request_Tests() :
         Text_Based_Test("misc/roughtime_request.vec", "Nonce,Request") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override
         {
         Test::Result result("roughtime request");

         const auto nonce = vars.get_req_bin("Nonce");
         const auto request_v = vars.get_req_bin("Request");

         const auto request = Botan::Roughtime::encode_request(nonce);
         result.test_eq(
            "encode",
            type == "Valid",
            request == Botan::typecast_copy<std::array<uint8_t, 1024>>(request_v.data()));

         return result;
         }
   };

BOTAN_REGISTER_TEST("roughtime", "roughtime_request", Roughtime_Request_Tests);


class Roughtime_Response_Tests final : public Text_Based_Test
   {
   public:
      Roughtime_Response_Tests() :
         Text_Based_Test("misc/roughtime_response.vec",
                         "Response",
                         "Nonce,Pubkey,MidpointMicroSeconds,RadiusMicroSeconds") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override
         {
         Test::Result result("roughtime response");

         const auto response_v = vars.get_req_bin("Response");
         const auto n = vars.has_key("Nonce") ? vars.get_req_bin("Nonce") : std::vector<uint8_t>(64);
         assert(n.size() == 64);
         const Botan::Roughtime::Nonce nonce(n);
         try
            {
            const auto response = Botan::Roughtime::Response::from_bits(response_v, nonce);

            const auto pubkey = vars.get_req_bin("Pubkey");
            assert(pubkey.size() == 32);

            if(!response.validate(Botan::Ed25519_PublicKey(pubkey)))
               {
               result.confirm("fail_validation", type == "Invalid");
               }
            else
               {
               const auto midpoint = Botan::Roughtime::Response::sys_microseconds64(
                                        std::chrono::microseconds(
                                           vars.get_req_u64("MidpointMicroSeconds")));
               const auto radius = std::chrono::microseconds(
                                      vars.get_req_u32("RadiusMicroSeconds"));

               result.confirm("midpoint", response.utc_midpoint() == midpoint);
               result.confirm("radius", response.utc_radius() == radius);
               result.confirm("OK", type == "Valid");
               }
            }
         catch(const Botan::Roughtime::Roughtime_Error& e)
            {
            result.confirm(e.what(), type == "Invalid");
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("roughtime", "roughtime_response", Roughtime_Response_Tests);

class Roughtime_nonce_from_blind_Tests final : public Text_Based_Test
   {
   public:
      Roughtime_nonce_from_blind_Tests() :
         Text_Based_Test("misc/roughtime_nonce_from_blind.vec", "Response,Blind,Nonce") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override
         {
         Test::Result result("roughtime nonce_from_blind");

         const auto response = vars.get_req_bin("Response");
         const auto blind = vars.get_req_bin("Blind");
         const auto nonce = vars.get_req_bin("Nonce");

         result.test_eq("fail_validation",
                        Botan::Roughtime::nonce_from_blind(response, blind) == nonce,
                        type == "Valid");

         return result;
         }
   };

BOTAN_REGISTER_TEST("roughtime", "roughtime_nonce_from_blind", Roughtime_nonce_from_blind_Tests);



class Roughtime final : public Test
   {
      Test::Result test_nonce()
         {
         Test::Result result("roughtime nonce");

         auto rand64 = Botan::unlock(Test::rng().random_vec(64));;
         Botan::Roughtime::Nonce nonce_v(rand64);
         result.confirm("nonce from vector", nonce_v.get_nonce() == Botan::typecast_copy<std::array<uint8_t, 64>>
                        (rand64.data()));
         Botan::Roughtime::Nonce nonce_a(Botan::typecast_copy<std::array<uint8_t, 64>>(rand64.data()));
         result.confirm("nonce from array", nonce_v.get_nonce() == Botan::typecast_copy<std::array<uint8_t, 64>>(rand64.data()));
         rand64.push_back(10);
         result.test_throws("vector oversize", [&rand64]() {Botan::Roughtime::Nonce nonce_v2(rand64);}); //size 65
         rand64.pop_back();
         rand64.pop_back();
         result.test_throws("vector undersize", [&rand64]() {Botan::Roughtime::Nonce nonce_v2(rand64);}); //size 63

         return result;
         }

      Test::Result test_chain()
         {
         Test::Result result("roughtime chain");

         Botan::Roughtime::Chain c1;
         result.confirm("default constructed is empty", c1.links().empty() && c1.responses().empty());

         auto rand64 = Botan::unlock(Test::rng().random_vec(64));;
         Botan::Roughtime::Nonce nonce_v(rand64);
         result.confirm("empty chain nonce is blind",
                        c1.next_nonce(nonce_v).get_nonce() == Botan::typecast_copy<std::array<uint8_t, 64>>(rand64.data()));

         const std::string chain_str =
            "ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= eu9yhsJfVfguVSqGZdE8WKIxaBBM0ZG3Vmuc+IyZmG2YVmrIktUByDdwIFw6F4rZqmSFsBO85ljoVPz5bVPCOw== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWBnGOEajOwPA6G7oL47seBP4C7eEpr57H43C2/fK/kMA0UGZVUdf4KNX8oxOK6JIcsbVk8qhghTwA70qtwpYmQkDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AJrA8tEqPBQAqisiuAxgy2Pj7UJAiWbCdzGz1xcCnja3T+AqhC8fwpeIwW4GPy/vEb/awXW2DgSLKJfzWIAz+2lsR7t4UjNPvAgAAAEAAAABTSUcAREVMRes9Ch4X0HIw5KdOTB8xK4VDFSJBD/G9t7Et/CU7UW61OiTBXYYQTG2JekWZmGa0OHX1JPGG+APkpbsNw0BKUgYDAAAAIAAAACgAAABQVUJLTUlOVE1BWFR/9BWjpsWTQ1f6iUJea3EfZ1MkX3ftJiV3ABqNLpncFwAAAAAAAAAA//////////8AAAAA\n"
            "ed25519 gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo= uLeTON9D+2HqJMzK6sYWLNDEdtBl9t/9yw1cVAOm0/sONH5Oqdq9dVPkC9syjuWbglCiCPVF+FbOtcxCkrgMmA== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWOw1jl0uSiBEH9HE8/6r7zxoSc01f48vw+UzH8+VJoPelnvVJBj4lnH8uRLh5Aw0i4Du7XM1dp2u0r/I5PzhMQoDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AUBo+tEqPBQC47l77to7ESFTVhlw1SC74P5ssx6gpuJ6eP+1916GuUiySGE/x3Fp0c3otUGAdsRQou5p9PDTeane/YEeVq4/8AgAAAEAAAABTSUcAREVMRe5T1ml8wHyWAcEtHP/U5Rg/jFXTEXOSglngSa4aI/CECVdy4ZNWeP6vv+2//ZW7lQsrWo7ZkXpvm9BdBONRSQIDAAAAIAAAACgAAABQVUJLTUlOVE1BWFQpXlenV0OfVisvp9jDHXLw8vymZVK9Pgw9k6Edf8ZEhUgSGEc5jwUASHLvZE2PBQAAAAAA\n";

         Botan::Roughtime::Chain c2(chain_str);
         result.confirm("have two elements", c2.links().size() == 2 && c2.responses().size() == 2);
         result.confirm("serialize loopback", c2.to_string() == chain_str);

         c1.append(c2.links()[0], 1);
         result.confirm("append ok", c1.links().size() == 1 && c1.responses().size() == 1);
         c1.append(c2.links()[1], 1);
         result.confirm("max size", c1.links().size() == 1 && c1.responses().size() == 1);

         result.test_throws("non-positive max chain size", [&]() {c1.append(c2.links()[1], 0);});
         result.test_throws("1 field", [&]() {Botan::Roughtime::Chain a("ed25519");});
         result.test_throws("2 fields", [&]() {Botan::Roughtime::Chain a("ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE=");});
         result.test_throws("3 fields", [&]() {Botan::Roughtime::Chain a("ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= eu9yhsJfVfguVSqGZdE8WKIxaBBM0ZG3Vmuc+IyZmG2YVmrIktUByDdwIFw6F4rZqmSFsBO85ljoVPz5bVPCOw==");});
         result.test_throws("5 fields", [&]() {Botan::Roughtime::Chain a("ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= eu9yhsJfVfguVSqGZdE8WKIxaBBM0ZG3Vmuc+IyZmG2YVmrIktUByDdwIFw6F4rZqmSFsBO85ljoVPz5bVPCOw== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWBnGOEajOwPA6G7oL47seBP4C7eEpr57H43C2/fK/kMA0UGZVUdf4KNX8oxOK6JIcsbVk8qhghTwA70qtwpYmQkDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AJrA8tEqPBQAqisiuAxgy2Pj7UJAiWbCdzGz1xcCnja3T+AqhC8fwpeIwW4GPy/vEb/awXW2DgSLKJfzWIAz+2lsR7t4UjNPvAgAAAEAAAABTSUcAREVMRes9Ch4X0HIw5KdOTB8xK4VDFSJBD/G9t7Et/CU7UW61OiTBXYYQTG2JekWZmGa0OHX1JPGG+APkpbsNw0BKUgYDAAAAIAAAACgAAABQVUJLTUlOVE1BWFR/9BWjpsWTQ1f6iUJea3EfZ1MkX3ftJiV3ABqNLpncFwAAAAAAAAAA//////////8AAAAA abc");});
         result.test_throws("invalid key type", [&]() {Botan::Roughtime::Chain a("rsa bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= eu9yhsJfVfguVSqGZdE8WKIxaBBM0ZG3Vmuc+IyZmG2YVmrIktUByDdwIFw6F4rZqmSFsBO85ljoVPz5bVPCOw== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWBnGOEajOwPA6G7oL47seBP4C7eEpr57H43C2/fK/kMA0UGZVUdf4KNX8oxOK6JIcsbVk8qhghTwA70qtwpYmQkDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AJrA8tEqPBQAqisiuAxgy2Pj7UJAiWbCdzGz1xcCnja3T+AqhC8fwpeIwW4GPy/vEb/awXW2DgSLKJfzWIAz+2lsR7t4UjNPvAgAAAEAAAABTSUcAREVMRes9Ch4X0HIw5KdOTB8xK4VDFSJBD/G9t7Et/CU7UW61OiTBXYYQTG2JekWZmGa0OHX1JPGG+APkpbsNw0BKUgYDAAAAIAAAACgAAABQVUJLTUlOVE1BWFR/9BWjpsWTQ1f6iUJea3EfZ1MkX3ftJiV3ABqNLpncFwAAAAAAAAAA//////////8AAAAA");});
         result.test_throws("invalid key", [&]() {Botan::Roughtime::Chain a("ed25519 bbT+RPS7zKX6wssPibzmwWqU9ffRV5oj2OresSmhE= eu9yhsJfVfguVSqGZdE8WKIxaBBM0ZG3Vmuc+IyZmG2YVmrIktUByDdwIFw6F4rZqmSFsBO85ljoVPz5bVPCOw== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWBnGOEajOwPA6G7oL47seBP4C7eEpr57H43C2/fK/kMA0UGZVUdf4KNX8oxOK6JIcsbVk8qhghTwA70qtwpYmQkDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AJrA8tEqPBQAqisiuAxgy2Pj7UJAiWbCdzGz1xcCnja3T+AqhC8fwpeIwW4GPy/vEb/awXW2DgSLKJfzWIAz+2lsR7t4UjNPvAgAAAEAAAABTSUcAREVMRes9Ch4X0HIw5KdOTB8xK4VDFSJBD/G9t7Et/CU7UW61OiTBXYYQTG2JekWZmGa0OHX1JPGG+APkpbsNw0BKUgYDAAAAIAAAACgAAABQVUJLTUlOVE1BWFR/9BWjpsWTQ1f6iUJea3EfZ1MkX3ftJiV3ABqNLpncFwAAAAAAAAAA//////////8AAAAA");});
         result.test_throws("invalid nonce", [&]() {Botan::Roughtime::Chain a("ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= eu9yhsJfVfguVSqGZdE8WKIxaBBM0ZG3Vmuc+IyZmG2UByDdwIFw6F4rZqmSFsBO85ljoVPz5bVPCOw== BQAAAEAAAABAAAAApAAAADwBAABTSUcAUEFUSFNSRVBDRVJUSU5EWBnGOEajOwPA6G7oL47seBP4C7eEpr57H43C2/fK/kMA0UGZVUdf4KNX8oxOK6JIcsbVk8qhghTwA70qtwpYmQkDAAAABAAAAAwAAABSQURJTUlEUFJPT1RAQg8AJrA8tEqPBQAqisiuAxgy2Pj7UJAiWbCdzGz1xcCnja3T+AqhC8fwpeIwW4GPy/vEb/awXW2DgSLKJfzWIAz+2lsR7t4UjNPvAgAAAEAAAABTSUcAREVMRes9Ch4X0HIw5KdOTB8xK4VDFSJBD/G9t7Et/CU7UW61OiTBXYYQTG2JekWZmGa0OHX1JPGG+APkpbsNw0BKUgYDAAAAIAAAACgAAABQVUJLTUlOVE1BWFR/9BWjpsWTQ1f6iUJea3EfZ1MkX3ftJiV3ABqNLpncFwAAAAAAAAAA//////////8AAAAA");});

         return result;
         }

      Test::Result test_server_information()
         {
         Test::Result result("roughtime server_information");

         const auto servers = Botan::Roughtime::servers_from_str(
                                 "Chainpoint-Roughtime ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= udp roughtime.chainpoint.org:2002\n"
                                 "Cloudflare-Roughtime ed25519 gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo= udp roughtime.cloudflare.com:2002\n"
                                 "Google-Sandbox-Roughtime ed25519 etPaaIxcBMY1oUeGpwvPMCJMwlRVNxv51KK/tktoJTQ= udp roughtime.sandbox.google.com:2002\n"
                                 "int08h-Roughtime ed25519 AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE= udp roughtime.int08h.com:2002\n"
                                 "ticktock ed25519 cj8GsiNlRkqiDElAeNMSBBMwrAl15hYPgX50+GWX/lA= udp ticktock.mixmin.net:5333\n"
                              );

         result.confirm("size", servers.size() == 5);
         result.test_eq("name", servers[0].name(), "Chainpoint-Roughtime");
         result.test_eq("name", servers[4].name(), "ticktock");
         result.confirm("public key", servers[0].public_key().get_public_key() == Botan::Ed25519_PublicKey(
                           Botan::base64_decode("bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE=")).get_public_key());
         result.confirm("single address", servers[0].addresses().size()==1);
         result.test_eq("address", servers[0].addresses()[0], "roughtime.chainpoint.org:2002");

         result.test_throws("1 field", [&]() {Botan::Roughtime::servers_from_str("A");});
         result.test_throws("2 fields", [&]() {Botan::Roughtime::servers_from_str("A ed25519");});
         result.test_throws("3 fields", [&]() {Botan::Roughtime::servers_from_str("A ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE=");});
         result.test_throws("4 fields", [&]() {Botan::Roughtime::servers_from_str("A ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= udp");});
         result.test_throws("invalid address", [&]() {Botan::Roughtime::servers_from_str("A ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= udp ");});
         result.test_throws("invalid key type", [&]() {Botan::Roughtime::servers_from_str("A rsa bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= udp roughtime.chainpoint.org:2002");});
         result.test_throws("invalid key", [&]() {Botan::Roughtime::servers_from_str("A ed25519 bbT+RP7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= udp roughtime.chainpoint.org:2002");});
         result.test_throws("invalid protocol", [&]() {Botan::Roughtime::servers_from_str("A ed25519 bbT+RPS7zKX6w71ssPibzmwWqU9ffRV5oj2OresSmhE= tcp roughtime.chainpoint.org:2002");});

         return result;
         }

      Test::Result test_request_online()
         {
         Test::Result result("roughtime request online");

         Botan::Roughtime::Nonce nonce(Test::rng());
         try
            {
            const auto response_raw = Botan::Roughtime::online_request("roughtime.cloudflare.com:2002", nonce,
                                      std::chrono::seconds(5));
            const auto now = std::chrono::system_clock::now();
            const auto response = Botan::Roughtime::Response::from_bits(response_raw, nonce);
            std::chrono::milliseconds local_clock_max_error(1000);
            const auto diff_abs = now >= response.utc_midpoint() ? now - response.utc_midpoint() : response.utc_midpoint() - now;
            result.confirm("online", diff_abs <= (response.utc_radius() + local_clock_max_error));
            }
         catch(const std::exception& e)
            {
            result.test_failure(e.what());
            }
         return result;
         }


   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;
         results.push_back(test_nonce());
         results.push_back(test_chain());
         results.push_back(test_server_information());

         if(Test::options().run_online_tests())
            {
            results.push_back(test_request_online());
            }

         return results;
         }
   };

BOTAN_REGISTER_TEST("roughtime", "roughtime", Roughtime);

#endif

}
