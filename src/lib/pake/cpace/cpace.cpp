/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpace.h>
#include <botan/hash.h>

namespace Botan {

/*

     Inputs
       H   = SHA-256 with input block size 64 bytes.
       PRS = b'Password' ; ZPAD length: 23 ;
       DSI = b'CPaceP256_XMD:SHA-256_SSWU_NU_'
       CI = b'\nAinitiator\nBresponder'
       CI = 0a41696e69746961746f720a42726573706f6e646572
       sid = 34b36454cab2e7842c389f7d88ecb7df
     Outputs
       generator_string(PRS,G.DSI,CI,sid,H.s_in_bytes):
       (length: 104 bytes)
         1e4350616365503235365f584d443a5348412d3235365f535357555f
         4e555f0850617373776f726417000000000000000000000000000000
         0000000000000000160a41696e69746961746f720a42726573706f6e
         6465721034b36454cab2e7842c389f7d88ecb7df
       generator g: (length: 65 bytes)
         04993b46e30ba9cfc3dc2d3ae2cf9733cf03994e74383c4e1b4a92e8
         d6d466b321c4a642979162fbde9e1c9a6180bd27a0594491e4c231f5
         1006d0bf7992d07127

B.5.2.  Test vector for MSGa

     Inputs
       ADa = b'ADa'
       ya (big endian): (length: 32 bytes)
         c9e47ca5debd2285727af47e55f5b7763fa79719da428f800190cc66
         59b4eafb
     Outputs
       Ya: (length: 65 bytes)
         0478ac925a6e3447a537627a2163be005a422f55c08385c1ef7d051c
         a94593df5946314120faa87165cba131c1da3aac429dc3d99a9bac7d
         4c4cbb8570b4d5ea10
       Alternative correct value for Ya: g^(-ya):
       (length: 65 bytes)
         0478ac925a6e3447a537627a2163be005a422f55c08385c1ef7d051c
         a94593df59b9cebede05578e9b345ece3e25c553bd623c2666645382
         b3b3447a8f4b2a15ef
       MSGa = lv_cat(Ya,ADa): (length: 70 bytes)
         410478ac925a6e3447a537627a2163be005a422f55c08385c1ef7d05
         1ca94593df5946314120faa87165cba131c1da3aac429dc3d99a9bac
         7d4c4cbb8570b4d5ea1003414461

B.5.3.  Test vector for MSGb

     Inputs
       ADb = b'ADb'
       yb (big endian): (length: 32 bytes)
         a0b768ba7555621d133012d1dee27a0013c1bcfddd675811df12771e
         44d77b10
     Outputs
       Yb: (length: 65 bytes)
         04df13ffa89b0ce3cc553b1495ff027886564d94b8d9165cd50e5f65
         4247959951bfac90839fca218bf8e2d1258eb7d7d9f733fe4cd558e6
         fa57bf1f801aae7d3a
       Alternative correct value for Yb: g^(-yb):
       (length: 65 bytes)
         04df13ffa89b0ce3cc553b1495ff027886564d94b8d9165cd50e5f65
         424795995140536f7b6035de75071d2eda7148282608cc01b42aa719
         05a840e07fe55182c5
       MSGb = lv_cat(Yb,ADb): (length: 70 bytes)
         4104df13ffa89b0ce3cc553b1495ff027886564d94b8d9165cd50e5f
         654247959951bfac90839fca218bf8e2d1258eb7d7d9f733fe4cd558
         e6fa57bf1f801aae7d3a03414462

B.5.4.  Test vector for secret points K

       scalar_mult_vfy(ya,Yb): (length: 32 bytes)
         27f7059d88f02007dc18c911c9b4034d3c0f13f8f7ed9603b0927f23
         fbab1037
       scalar_mult_vfy(yb,Ya): (length: 32 bytes)
         27f7059d88f02007dc18c911c9b4034d3c0f13f8f7ed9603b0927f23
         fbab1037

B.5.5.  Test vector for ISK calculation initiator/responder

       unordered cat of transcript : (length: 140 bytes)
         410478ac925a6e3447a537627a2163be005a422f55c08385c1ef7d05
         1ca94593df5946314120faa87165cba131c1da3aac429dc3d99a9bac
         7d4c4cbb8570b4d5ea10034144614104df13ffa89b0ce3cc553b1495
         ff027886564d94b8d9165cd50e5f654247959951bfac90839fca218b
         f8e2d1258eb7d7d9f733fe4cd558e6fa57bf1f801aae7d3a03414462
       DSI = G.DSI_ISK, b'CPaceP256_XMD:SHA-256_SSWU_NU__ISK':
       (length: 34 bytes)
         4350616365503235365f584d443a5348412d3235365f535357555f4e
         555f5f49534b
       lv_cat(DSI,sid,K)||MSGa||MSGb: (length: 225 bytes)
         224350616365503235365f584d443a5348412d3235365f535357555f
         4e555f5f49534b1034b36454cab2e7842c389f7d88ecb7df2027f705
         9d88f02007dc18c911c9b4034d3c0f13f8f7ed9603b0927f23fbab10
         37410478ac925a6e3447a537627a2163be005a422f55c08385c1ef7d
         051ca94593df5946314120faa87165cba131c1da3aac429dc3d99a9b
         ac7d4c4cbb8570b4d5ea10034144614104df13ffa89b0ce3cc553b14
         95ff027886564d94b8d9165cd50e5f654247959951bfac90839fca21
         8bf8e2d1258eb7d7d9f733fe4cd558e6fa57bf1f801aae7d3a034144
         62
       ISK result: (length: 32 bytes)
         ddc1b133c387ecf344c0b496bc1223656cd6e7d99a5def8b3b026796
         50811fc9

B.5.6.  Test vector for ISK calculation parallel execution

       ordered cat of transcript : (length: 140 bytes)
         4104df13ffa89b0ce3cc553b1495ff027886564d94b8d9165cd50e5f
         654247959951bfac90839fca218bf8e2d1258eb7d7d9f733fe4cd558
         e6fa57bf1f801aae7d3a03414462410478ac925a6e3447a537627a21
         63be005a422f55c08385c1ef7d051ca94593df5946314120faa87165
         cba131c1da3aac429dc3d99a9bac7d4c4cbb8570b4d5ea1003414461
       DSI = G.DSI_ISK, b'CPaceP256_XMD:SHA-256_SSWU_NU__ISK':
       (length: 34 bytes)
         4350616365503235365f584d443a5348412d3235365f535357555f4e
         555f5f49534b
       lv_cat(DSI,sid,K)||oCAT(MSGa,MSGb): (length: 225 bytes)
         224350616365503235365f584d443a5348412d3235365f535357555f
         4e555f5f49534b1034b36454cab2e7842c389f7d88ecb7df2027f705
         9d88f02007dc18c911c9b4034d3c0f13f8f7ed9603b0927f23fbab10
         374104df13ffa89b0ce3cc553b1495ff027886564d94b8d9165cd50e
         5f654247959951bfac90839fca218bf8e2d1258eb7d7d9f733fe4cd5
         58e6fa57bf1f801aae7d3a03414462410478ac925a6e3447a537627a
         2163be005a422f55c08385c1ef7d051ca94593df5946314120faa871
         65cba131c1da3aac429dc3d99a9bac7d4c4cbb8570b4d5ea10034144
         61
       ISK result: (length: 32 bytes)
         6ea775b0fb3c31502687565a52150fc595c63fe901a11d5fc1995cd5
         089a17ae
*/

#if 0
PAKE_Cpace::PAKE_Cpace(std::string_view group_id, std::string_view hash_fn) {
}

PAKE_Cpace::~PAKE_Cpace() = default;

PasswordAuthenticatedKeyExchange::Status PAKE_Cpace::status() const {

}

std::vector<uint8_t>
PAKE_Cpace::begin(std::string_view password,
                  std::span<const uint8_t> channel_id,
                  std::span<const uint8_t> session_id,
                  std::span<const uint8_t> assoc_a,
                  std::span<const uint8_t> assoc_b) {
}

std::optional<std::vector<uint8_t>> PAKE_Cpace::step(std::span<const uint8_t> peer_message) {
}

std::vector<uint8_t> PAKE_Cpace::shared_secret() const {
}

#endif

EC_Point cpace_generator(const EC_Group& group,
                         const std::string& password,
                         std::span<const uint8_t> channel_id,
                         std::span<const uint8_t> session_id) {


}

}  // namespace Botan
