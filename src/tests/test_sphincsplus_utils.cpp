/*
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_SPHINCS_PLUS_COMMON) && defined(BOTAN_HAS_SHA2_32)

   #include <botan/hex.h>
   #include <botan/internal/sp_address.h>

namespace Botan_Tests {

namespace {

std::vector<Test::Result> test_sphincsplus_address() {
   auto sha256 = [](const Botan::Sphincs_Address& adrs) {
      auto h = Botan::HashFunction::create_or_throw("SHA-256");
      h->update(adrs.to_bytes());
      return h->final_stdvec();
   };

   return {
      CHECK("default address",
            [&](Test::Result& result) {
               Botan::Sphincs_Address a({0, 0, 0, 0, 0, 0, 0, 0});
               result.test_is_eq("SHA-256(32*0x00)",
                                 sha256(a),
                                 Botan::hex_decode("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"));
            }),

      CHECK("set up an address",
            [&](Test::Result& result) {
               Botan::Sphincs_Address a(Botan::Sphincs_Address::ForsTree);
               a.set_layer_address(Botan::HypertreeLayerIndex(1337))
                  .set_tree_address(Botan::XmssTreeIndexInLayer(4294967338) /* longer than 32bits */)
                  .set_keypair_address(Botan::TreeNodeIndex(131072))
                  .set_chain_address(Botan::WotsChainIndex(67108864))
                  .set_hash_address(Botan::WotsHashIndex(42));

               result.test_is_eq("SHA-256(a1)",
                                 sha256(a),
                                 Botan::hex_decode("aecc0696fee5c4aa601779343d01090aae0d0a3b6cf118d3c7245d48dc0f3af9"));
            }),

      CHECK("set up another address",
            [&](Test::Result& result) {
               Botan::Sphincs_Address a(Botan::Sphincs_Address::ForsTree);
               a.set_layer_address(Botan::HypertreeLayerIndex(1337))
                  .set_tree_address(Botan::XmssTreeIndexInLayer(4294967338) /* longer than 32bits */)
                  .set_keypair_address(Botan::TreeNodeIndex(131072))
                  .set_tree_height(Botan::TreeLayerIndex(67108864))
                  .set_tree_index(Botan::TreeNodeIndex(1073741824));
               result.test_is_eq("SHA-256(a2)",
                                 sha256(a),
                                 Botan::hex_decode("607fdc9d063168fbea64e4da2a255693314712d859062abb80cf7c78116ded2a"));
            }),

      CHECK("copy subtree",
            [&](Test::Result& result) {
               Botan::Sphincs_Address a(Botan::Sphincs_Address::ForsTree);
               a.set_layer_address(Botan::HypertreeLayerIndex(1337))
                  .set_tree_address(Botan::XmssTreeIndexInLayer(4294967338) /* longer than 32bits */)
                  .set_keypair_address(Botan::TreeNodeIndex(131072))
                  .set_tree_height(Botan::TreeLayerIndex(67108864))
                  .set_tree_index(Botan::TreeNodeIndex(1073741824));

               auto subtree1 = Botan::Sphincs_Address::as_subtree_from(a);
               Botan::Sphincs_Address subtree2({0, 0, 0, 0, 0, 0, 0, 0});
               subtree2.copy_subtree_from(a);

               result.test_is_eq("SHA-256(subtree1)",
                                 sha256(subtree1),
                                 Botan::hex_decode("f192c8f8e946aa16d16eafe88bd4eabcc88a305b69bb7c0bb49e65bd122bb973"));
               result.test_is_eq("SHA-256(subtree2)",
                                 sha256(subtree2),
                                 Botan::hex_decode("f192c8f8e946aa16d16eafe88bd4eabcc88a305b69bb7c0bb49e65bd122bb973"));
            }),

      CHECK("copy keypair",
            [&](Test::Result& result) {
               Botan::Sphincs_Address a(Botan::Sphincs_Address::ForsTree);
               a.set_layer_address(Botan::HypertreeLayerIndex(1337))
                  .set_tree_address(Botan::XmssTreeIndexInLayer(4294967338) /* longer than 32bits */)
                  .set_keypair_address(Botan::TreeNodeIndex(131072))
                  .set_chain_address(Botan::WotsChainIndex(67108864))
                  .set_hash_address(Botan::WotsHashIndex(42));

               auto keypair1 = Botan::Sphincs_Address::as_keypair_from(a);
               Botan::Sphincs_Address keypair2({0, 0, 0, 0, 0, 0, 0, 0});
               keypair2.copy_keypair_from(a);

               result.test_is_eq("SHA-256(keypair1)",
                                 sha256(keypair1),
                                 Botan::hex_decode("1cdd4835a6057306678e7d8cb903c140aba1d4805a8a1f75b11f1129bb22d08c"));
               result.test_is_eq("SHA-256(keypair2)",
                                 sha256(keypair2),
                                 Botan::hex_decode("1cdd4835a6057306678e7d8cb903c140aba1d4805a8a1f75b11f1129bb22d08c"));
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("pubkey", "sphincsplus_address", test_sphincsplus_address);

}  // namespace Botan_Tests

#endif  // BOTAN_HAS_SPHINCS_PLUS_COMMON
