#pragma once

#ifndef BOTAN_KYBER_KEY_H_
#define BOTAN_KYBER_KEY_H_

#include <botan/pk_keys.h>
#include <botan/exceptn.h>
#include <botan/der_enc.h>

#include <botan/hash.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {
    enum class KyberMode {
        Kyber512,
        Kyber512_90s,
        Kyber768,
        Kyber768_90s,
        Kyber1024,
        Kyber1024_90s
    };

    class Kyber_PublicKeyInternal;
    class Kyber_PrivateKeyInternal;

    class BOTAN_PUBLIC_API(2, 0) Kyber_PublicKey : public virtual Public_Key
    {
    public:

        Kyber_PublicKey( const std::vector<uint8_t>&pub_key, KyberMode mode );

        Kyber_PublicKey(const Kyber_PublicKey & other) = default;

        Kyber_PublicKey& operator=(const Kyber_PublicKey & other) = default;

        virtual ~Kyber_PublicKey() = default;

        std::string algo_name() const override;

        AlgorithmIdentifier algorithm_identifier() const override;

        size_t key_length() const override;

        size_t estimated_strength() const override;

        std::vector<uint8_t> public_key_bits() const override;

        bool check_key( RandomNumberGenerator&, bool ) const override;

        std::unique_ptr<PK_Ops::KEM_Encryption>
           create_kem_encryption_op(RandomNumberGenerator& rng,
                                    const std::string& params,
                                    const std::string& provider) const override;

    protected:
        Kyber_PublicKey() {};

    protected:
        friend class Kyber_KEM_Encryptor;
        friend class Kyber_KEM_Decryptor;

        std::shared_ptr<Kyber_PublicKeyInternal> m_public;
    };


    class BOTAN_PUBLIC_API(2, 0) Kyber_PrivateKey final : public virtual Kyber_PublicKey,
        public virtual Private_Key
    {
        public:

            Kyber_PrivateKey(RandomNumberGenerator& rng, KyberMode mode);

            Kyber_PrivateKey(secure_vector<uint8_t> sk, std::vector<uint8_t> pk, KyberMode mode);

            bool check_key( RandomNumberGenerator& rng, bool strong ) const override;

            secure_vector<uint8_t> private_key_bits() const override;

            std::unique_ptr<PK_Ops::KEM_Decryption>
               create_kem_decryption_op(RandomNumberGenerator& rng,
                                        const std::string& params,
                                        const std::string& provider) const override;
    private:
        friend class Kyber_KEM_Decryptor;

        std::shared_ptr<Kyber_PrivateKeyInternal> m_private;
    };

    /**
    * Estimate work factor for Kyber
    * @return estimated security level for these key parameters
    */
    //BOTAN_PUBLIC_API(2,0) size_t kyber_work_factor(size_t code_size, size_t t); 
 
}
#endif
