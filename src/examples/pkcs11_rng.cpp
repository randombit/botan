#include <botan/auto_rng.h>
#include <botan/hmac_drbg.h>
#include <botan/mac.h>
#include <botan/p11_randomgenerator.h>

#include <vector>

int main()
   {
   Botan::PKCS11::PKCS11_RNG p11_rng( session );

   /************ generate random data *************/
   std::vector<uint8_t> random( 20 );
   p11_rng.randomize( random.data(), random.size() );

   /************ add entropy *************/
   Botan::AutoSeeded_RNG auto_rng;
   auto auto_rng_random = auto_rng.random_vec( 20 );
   p11_rng.add_entropy( auto_rng_random.data(), auto_rng_random.size() );

   /************ use PKCS#11 RNG to seed HMAC_DRBG *************/
   Botan::HMAC_DRBG drbg( Botan::MessageAuthenticationCode::create( "HMAC(SHA-512)" ), p11_rng );
   drbg.randomize( random.data(), random.size() );
   }
