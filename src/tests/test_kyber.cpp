/*
* (C) 2021 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <botan/block_cipher.h>

#if defined(BOTAN_HAS_KYBER)
#include <botan/kyber.h>
#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#endif

namespace Botan_Tests {

    namespace {

#if defined(BOTAN_HAS_KYBER)

        // Kyber test RNG
#define RNG_SUCCESS      0
#define RNG_BAD_MAXLEN  -1
#define RNG_BAD_OUTBUF  -2
#define RNG_BAD_REQ_LEN -3

        void AES256_ECB( unsigned char* key, unsigned char* ctr, unsigned char* buffer );

        void AES256_CTR_DRBG_Update( unsigned char* provided_data, unsigned char* Key, unsigned char* V )
        {
            unsigned char   temp[48];

            for ( int i = 0; i < 3; i++ ) {
                //increment V
                for ( int j = 15; j >= 0; j-- ) {
                    if ( V[j] == 0xff )
                        V[j] = 0x00;
                    else {
                        V[j]++;
                        break;
                    }
                }

                AES256_ECB( Key, V, temp + 16 * i );
            }
            if ( provided_data != NULL )
                for ( int i = 0; i < 48; i++ )
                    temp[i] ^= provided_data[i];
            memcpy( Key, temp, 32 );
            memcpy( V, temp + 32, 16 );
        }

        //    key - 256-bit AES key
        //    ctr - a 128-bit plaintext value
        //    buffer - a 128-bit ciphertext value
        void AES256_ECB( unsigned char* key, unsigned char* ctr, unsigned char* buffer )
        {
            std::unique_ptr<Botan::BlockCipher> cipher( Botan::BlockCipher::create( "AES-256" ) );

            std::vector<uint8_t> keyAes( key, key + cipher->maximum_keylength() );
            std::vector<uint8_t> block( ctr, ctr + cipher->block_size() );


            cipher->set_key( keyAes );
            cipher->encrypt( block );

            std::copy( block.begin(), block.end(), buffer );
        }

        

        class Kyber_Test_RNG final : public Botan::RandomNumberGenerator
        {
        public:
            std::string name() const override { return "Kyber_Test_RNG"; }

            void clear() override
            {
                // reset struct
                memset( DRBG_ctx.Key, 0x00, 32 );
                memset( DRBG_ctx.V, 0x00, 16 );
                DRBG_ctx.reseed_counter = 0;
            }

            bool accepts_input() const override { return true; }

            void add_entropy( const uint8_t data[], size_t len ) override
            {
                BOTAN_UNUSED(len);
                randombytes_init( data, nullptr, 256 );
            }

            bool is_seeded() const override
            {
                return true;
            }

            void randomize( uint8_t out[], size_t len ) override
            {
                randombytes( out, len );
            }

            Kyber_Test_RNG( const std::vector<uint8_t>& seed )
            {
                clear();
                add_entropy( seed.data(), seed.size() );
            }

        private:
            void randombytes_init( const unsigned char* entropy_input, unsigned char* personalization_string, int security_strength )
            {
                BOTAN_UNUSED( security_strength );
                unsigned char   seed_material[48];

                memcpy( seed_material, entropy_input, 48 );
                if ( personalization_string )
                    for ( int i = 0; i < 48; i++ )
                        seed_material[i] ^= personalization_string[i];
                memset( DRBG_ctx.Key, 0x00, 32 );
                memset( DRBG_ctx.V, 0x00, 16 );
                AES256_CTR_DRBG_Update( seed_material, DRBG_ctx.Key, DRBG_ctx.V );
                DRBG_ctx.reseed_counter = 1;
            }

            int randombytes( unsigned char* x, size_t xlen )
            {
                unsigned char   block[16];
                int             i = 0;

                while ( xlen > 0 ) {
                    //increment V
                    for ( int j = 15; j >= 0; j-- ) {
                        if ( DRBG_ctx.V[j] == 0xff )
                            DRBG_ctx.V[j] = 0x00;
                        else {
                            DRBG_ctx.V[j]++;
                            break;
                        }
                    }
                    AES256_ECB( DRBG_ctx.Key, DRBG_ctx.V, block );
                    if ( xlen > 15 ) {
                        memcpy( x + i, block, 16 );
                        i += 16;
                        xlen -= 16;
                    }
                    else {
                        memcpy( x + i, block, xlen );
                        xlen = 0;
                    }
                }
                AES256_CTR_DRBG_Update( NULL, DRBG_ctx.Key, DRBG_ctx.V );
                DRBG_ctx.reseed_counter++;

                return RNG_SUCCESS;
            }

            typedef struct {
                unsigned char   Key[32];
                unsigned char   V[16];
                int             reseed_counter;
            } AES256_CTR_DRBG_struct;
            AES256_CTR_DRBG_struct  DRBG_ctx;
        };

        class KYBER_Tests final : public Test
        {
        public:
            Test::Result run_kyber_test( Botan::KyberMode mode )
            {
                std::string test_name;
                switch ( mode )
                {
                case Botan::KyberMode::Kyber512:
                    test_name = "kyber512 test API";
                    break;
                case Botan::KyberMode::Kyber768:
                    test_name = "kyber768 test API";
                    break;
                case Botan::KyberMode::Kyber1024:
                    test_name = "kyber1024 test API";
                    break;
                default:
                    throw std::runtime_error( "unknown kyber mode in run_kyber_test()" );;
                }

                Test::Result result( test_name );

                uint8_t salt[1];
                size_t shared_secret_length = 32;

                // Alice
                std::unique_ptr<Botan::RandomNumberGenerator> kyber_rng_alice;
                kyber_rng_alice.reset( new Botan::AutoSeeded_RNG );
                auto priv_key = Botan::Kyber_PrivateKey( *kyber_rng_alice, mode );

                // Bob
                std::unique_ptr<Botan::RandomNumberGenerator> kyber_rng_bob;
                kyber_rng_bob.reset( new Botan::AutoSeeded_RNG );
                auto pub_key = Botan::Kyber_PublicKey( priv_key.public_key_bits(), mode );
                auto enc = pub_key.create_kem_encryption_op( *kyber_rng_bob, "", "" );
                Botan::secure_vector<uint8_t> cipher_text, key_bob;
                enc->kem_encrypt( cipher_text, key_bob, shared_secret_length, *kyber_rng_bob, salt, 0 );

                // Alice
                auto dec = priv_key.create_kem_decryption_op( *kyber_rng_alice, "", "" );
                auto key_alice = dec->kem_decrypt( cipher_text.data(), cipher_text.size(), shared_secret_length, salt, 0 );

                result.test_eq( "Shared secrets are not equal!", key_alice == key_bob, true );
                return result;

            }
            std::vector<Test::Result> run() override
            {
                std::vector<Test::Result> results;

                results.push_back( run_kyber_test( Botan::KyberMode::Kyber512 ) );
                results.push_back( run_kyber_test( Botan::KyberMode::Kyber768 ) );
                results.push_back( run_kyber_test( Botan::KyberMode::Kyber1024 ) );

                return results;
            }
        };
        BOTAN_REGISTER_TEST( "kyber", "kyber_pairwise", KYBER_Tests );

        Test::Result run_kyber_test_internal( const VarMap& vars, Botan::KyberMode mode )
        {
            const auto round = vars.get_req_sz( "count" );
            std::string mode_str;
            switch ( mode )
            {
            case Botan::KyberMode::Kyber512:
                mode_str = "Kyber512";
                break;
                case Botan::KyberMode::Kyber512_90s:
                mode_str = "Kyber512_90s";
                break;
            case Botan::KyberMode::Kyber768:
                mode_str = "Kyber768";
                break;
            case Botan::KyberMode::Kyber768_90s:
                mode_str = "Kyber768_90s";
                break;
            case Botan::KyberMode::Kyber1024:
                mode_str = "Kyber1024";
                break;
            case Botan::KyberMode::Kyber1024_90s:
                mode_str = "Kyber1024_90s";
                break;
            default:
                mode_str = "unknown Kyber mode";
            }

            Test::Result result( mode_str + " round " + std::to_string( round ) );

            // read input from test file
            std::vector<uint8_t> seed_in = vars.get_req_bin( "seed" );
            std::vector<uint8_t> pk_in = vars.get_req_bin( "pk" );
            std::vector<uint8_t> sk_in = vars.get_req_bin( "sk" );
            std::vector<uint8_t> ct_in = vars.get_req_bin( "ct" );
            std::vector<uint8_t> ss_in = vars.get_req_bin( "ss" );

            uint8_t salt[1];
            size_t shared_secret_length = 32;

            // Kyber test RNG
            std::unique_ptr<Botan::RandomNumberGenerator> kyber_test_rng;
            kyber_test_rng.reset( new Kyber_Test_RNG( seed_in ) );

            // Alice
            auto priv_key = Botan::Kyber_PrivateKey( *kyber_test_rng, mode );
            result.test_eq( "Public Key Output", priv_key.public_key_bits(), pk_in );
            result.test_eq( "Secret Key Output", priv_key.private_key_bits(), sk_in );

            // Bob
            auto pub_key = Botan::Kyber_PublicKey( priv_key.public_key_bits(), mode );
            auto enc = pub_key.create_kem_encryption_op( *kyber_test_rng, "", "" );
            Botan::secure_vector<uint8_t> cipher_text, key_bob;
            enc->kem_encrypt( cipher_text, key_bob, shared_secret_length, *kyber_test_rng, salt, 0 );
            result.test_eq( "Cipher-Text Output", cipher_text, ct_in );
            result.test_eq( "Key B Output", key_bob, ss_in );

            // Alice
            auto dec = priv_key.create_kem_decryption_op( *kyber_test_rng, "", "" );
            auto key_alice = dec->kem_decrypt( cipher_text.data(), cipher_text.size(), shared_secret_length, salt, 0 );
            result.test_eq( "Key A Output", key_alice, ss_in );

            return result;
        }

        class KYBER_KAT_512 final : public Text_Based_Test
        {
        public:
            KYBER_KAT_512() : Text_Based_Test( "pubkey/kyber_512.vec", "count,seed,pk,sk,ct,ss" ) {}


            Test::Result run_one_test( const std::string&, const VarMap& vars ) override
            {
                return run_kyber_test_internal( vars, Botan::KyberMode::Kyber512 );
            }
        };
        BOTAN_REGISTER_TEST( "kyber", "kyber_kat_512", KYBER_KAT_512 );

        class KYBER_KAT_768 final : public Text_Based_Test
        {
        public:
            KYBER_KAT_768() : Text_Based_Test( "pubkey/kyber_768.vec", "count,seed,pk,sk,ct,ss" ) {}


            Test::Result run_one_test( const std::string&, const VarMap& vars ) override
            {
                return run_kyber_test_internal( vars, Botan::KyberMode::Kyber768 );
            }
        };
        BOTAN_REGISTER_TEST( "kyber", "kyber_kat_768", KYBER_KAT_768 );

        class KYBER_KAT_1024 final : public Text_Based_Test
        {
        public:
            KYBER_KAT_1024() : Text_Based_Test( "pubkey/kyber_1024.vec", "count,seed,pk,sk,ct,ss" ) {}


            Test::Result run_one_test( const std::string&, const VarMap& vars ) override
            {
                return run_kyber_test_internal( vars, Botan::KyberMode::Kyber1024 );
            }
        };
        BOTAN_REGISTER_TEST( "kyber", "kyber_kat_1024", KYBER_KAT_1024 );

        class KYBER_KAT_512_90s final : public Text_Based_Test
        {
        public:
            KYBER_KAT_512_90s() : Text_Based_Test( "pubkey/kyber_512_90s.vec", "count,seed,pk,sk,ct,ss" ) {}


            Test::Result run_one_test( const std::string&, const VarMap& vars ) override
            {
                return run_kyber_test_internal( vars, Botan::KyberMode::Kyber512_90s );
            }
        };
        BOTAN_REGISTER_TEST( "kyber", "kyber_kat_512_90s", KYBER_KAT_512_90s );

        class KYBER_KAT_768_90s final : public Text_Based_Test
        {
        public:
            KYBER_KAT_768_90s() : Text_Based_Test( "pubkey/kyber_768_90s.vec", "count,seed,pk,sk,ct,ss" ) {}


            Test::Result run_one_test( const std::string&, const VarMap& vars ) override
            {
                return run_kyber_test_internal( vars, Botan::KyberMode::Kyber768_90s );
            }
        };
        BOTAN_REGISTER_TEST( "kyber", "kyber_kat_768_90s", KYBER_KAT_768_90s );

        class KYBER_KAT_1024_90s final : public Text_Based_Test
        {
        public:
            KYBER_KAT_1024_90s() : Text_Based_Test( "pubkey/kyber_1024_90s.vec", "count,seed,pk,sk,ct,ss" ) {}


            Test::Result run_one_test( const std::string&, const VarMap& vars ) override
            {
                return run_kyber_test_internal( vars, Botan::KyberMode::Kyber1024_90s );
            }
        };
        BOTAN_REGISTER_TEST( "kyber", "kyber_kat_1024_90s", KYBER_KAT_1024_90s );
#endif

    }

}
