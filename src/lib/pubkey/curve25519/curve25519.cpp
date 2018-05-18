/*
* Curve25519
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/curve25519.h>
#include <botan/internal/ed25519_internal.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/rng.h>
#include <botan/sha2_64.h>
#include <stdlib.h>


namespace Botan {


	/**
	* Ed25519 signing operation ('C25519' - signs with a Curve25519 key)
	*/
	class Ed25519_C25519_Sign_Operation : public PK_Ops::Signature
	{
	public:
		Ed25519_C25519_Sign_Operation(const Curve25519_PrivateKey& key) : m_key(key)
		{
		}

		void update(const uint8_t msg[], size_t msg_len) override
		{
			m_msg.insert(m_msg.end(), msg, msg + msg_len);
		}

		secure_vector<uint8_t> sign(RandomNumberGenerator& rng) override
		{
			secure_vector<uint8_t> sig(64);
			std::vector<uint8_t> rand;
			rand.resize(64);
			rng.randomize(rand.data(), 64);
			secure_vector<uint8_t> privKey25519RAW;

			BER_Decoder(m_key.private_key_bits()).decode(privKey25519RAW, Botan::ASN1_Tag::OCTET_STRING).discard_remaining();

			curve25519_sign(sig.data(), privKey25519RAW.data(), m_msg.data(), m_msg.size(), rand.data());

			m_msg.clear();
			return sig;

		}

	private:
		std::vector<uint8_t> m_msg;
		const Curve25519_PrivateKey& m_key;
	};

	/**
	* Ed255190_C25519 verifying operation
	*/
	class Ed25519_C25519_Verify_Operation : public PK_Ops::Verification
	{
	public:
		Ed25519_C25519_Verify_Operation(const Curve25519_PublicKey& key) : m_key(key)
		{
		}

		void update(const uint8_t msg[], size_t msg_len) override
		{
			m_msg.insert(m_msg.end(), msg, msg + msg_len);
		}

		bool is_valid_signature(const uint8_t sig[], size_t sig_len) override
		{
			if (sig_len != 64)
				return false;

			bool ok = curve25519_verify(sig, m_key.public_key_bits().data(), m_msg.data(), m_msg.size());
			m_msg.clear();
			return ok;
		}

	private:
		std::vector<uint8_t> m_msg;
		const Curve25519_PublicKey& m_key;
	};

void curve25519_basepoint(uint8_t mypublic[32], const uint8_t secret[32])
   {
   const uint8_t basepoint[32] = { 9 };
   curve25519_donna(mypublic, secret, basepoint);
   }

namespace {

void size_check(size_t size, const char* thing)
   {
   if(size != 32)
      throw Decoding_Error("Invalid size " + std::to_string(size) + " for Curve25519 " + thing);
   }

secure_vector<uint8_t> curve25519(const secure_vector<uint8_t>& secret,
                               const uint8_t pubval[32])
   {
   secure_vector<uint8_t> out(32);
   curve25519_donna(out.data(), secret.data(), pubval);
   return out;
   }

}

AlgorithmIdentifier Curve25519_PublicKey::algorithm_identifier() const
   {
   // AlgorithmIdentifier::USE_NULL_PARAM puts 0x05 0x00 in parameters
   // We want nothing
   std::vector<uint8_t> empty;
   return AlgorithmIdentifier(get_oid(), empty);
   }

bool Curve25519_PublicKey::check_key(RandomNumberGenerator&, bool) const
   {
   return true; // no tests possible?
   }

Curve25519_PublicKey::Curve25519_PublicKey(const AlgorithmIdentifier&,
                                           const std::vector<uint8_t>& key_bits)
   {
   m_public = key_bits;

   size_check(m_public.size(), "public key");
   }

std::vector<uint8_t> Curve25519_PublicKey::public_key_bits() const
   {
   return m_public;
   }

std::unique_ptr<PK_Ops::Verification>
Curve25519_PublicKey::create_verification_op(const std::string& params,
	const std::string& provider) const
{
	if (provider == "base" || provider.empty())
	{
		if (params == "" || params == "Pure")
			return std::unique_ptr<PK_Ops::Verification>(new Ed25519_C25519_Verify_Operation(*this));

	}
	throw Provider_Not_Found(algo_name(), provider);
}

Curve25519_PrivateKey::Curve25519_PrivateKey(const secure_vector<uint8_t>& secret_key)
   {
   if(secret_key.size() != 32)
     throw Decoding_Error("Invalid size for Curve25519 private key");

   m_public.resize(32);
   m_private = secret_key;
   curve25519_basepoint(m_public.data(), m_private.data());
   }

Curve25519_PrivateKey::Curve25519_PrivateKey(RandomNumberGenerator& rng)
   {
   m_private = rng.random_vec(32);
   m_public.resize(32);
   curve25519_basepoint(m_public.data(), m_private.data());
   }

Curve25519_PrivateKey::Curve25519_PrivateKey(const AlgorithmIdentifier&,
                                             const secure_vector<uint8_t>& key_bits)
   {
   BER_Decoder(key_bits).decode(m_private, OCTET_STRING).discard_remaining();

   size_check(m_private.size(), "private key");
   m_public.resize(32);
   curve25519_basepoint(m_public.data(), m_private.data());
   }

secure_vector<uint8_t> Curve25519_PrivateKey::private_key_bits() const
   {
   return DER_Encoder().encode(m_private, OCTET_STRING).get_contents();
   }

bool Curve25519_PrivateKey::check_key(RandomNumberGenerator&, bool) const
   {
   std::vector<uint8_t> public_point(32);
   curve25519_basepoint(public_point.data(), m_private.data());
   return public_point == m_public;
   }

secure_vector<uint8_t> Curve25519_PrivateKey::agree(const uint8_t w[], size_t w_len) const
   {
   size_check(w_len, "public value");
   return curve25519(m_private, w);
   }

namespace {

/**
* Curve25519 operation
*/
class Curve25519_KA_Operation final : public PK_Ops::Key_Agreement_with_KDF
   {
   public:

      Curve25519_KA_Operation(const Curve25519_PrivateKey& key, const std::string& kdf) :
         PK_Ops::Key_Agreement_with_KDF(kdf),
         m_key(key) {}

      secure_vector<uint8_t> raw_agree(const uint8_t w[], size_t w_len) override
         {
         return m_key.agree(w, w_len);
         }
   private:
      const Curve25519_PrivateKey& m_key;
   };

}



std::unique_ptr<PK_Ops::Key_Agreement>
Curve25519_PrivateKey::create_key_agreement_op(RandomNumberGenerator& /*rng*/,
                                               const std::string& params,
                                               const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Key_Agreement>(new Curve25519_KA_Operation(*this, params));
   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::Signature>
Curve25519_PrivateKey::create_signature_op(RandomNumberGenerator&,
	const std::string& params,
	const std::string& provider) const
{
	if (provider == "base" || provider.empty())
	{
		if (params == "Pure")
			return std::unique_ptr<PK_Ops::Signature>(new Ed25519_C25519_Sign_Operation(*this));

	}
	throw Provider_Not_Found(algo_name(), provider);
}

void clamp(unsigned char* a)
{
	a[0] &= 248; a[31] &= 127; a[31] |= 64;
}
int curve25519_sign(unsigned char* signature_out,
	const unsigned char* curve25519_privkey,
	const unsigned char* msg, const size_t msg_len,
	const unsigned char* random)
{
	std::vector<uint8_t> privkey(32);
	std::memcpy(privkey.data(), curve25519_privkey, 32);
	clamp(privkey.data());

	ge_p3 ed_pubkey_point; /* Ed25519 pubkey point */
	unsigned char ed_pubkey[32]; /* Ed25519 encoded pubkey */
	unsigned char *sigbuf; /* working buffer */
	unsigned char sign_bit = 0;

	if ((sigbuf = (unsigned char*)malloc(msg_len + 128)) == 0) {
		memset(signature_out, 0, 64);
		return -1;
	}

	/* Convert the Curve25519 privkey to an Ed25519 public key */
	ge_scalarmult_base(ed_pubkey, privkey.data());
	sign_bit = ed_pubkey[31] & 0x80;

	/* Perform an Ed25519 signature with explicit private key */
	ed25519_sign_modified(signature_out, msg, msg_len, privkey.data(),
		ed_pubkey, random);

	/* Encode the sign bit into signature (in unused high bit of S) */
	signature_out[63] &= 0x7F; /* bit should be zero already, but just in case */
	signature_out[63] |= sign_bit;

	free(sigbuf);
	return 0;
}

int ed25519_sign_modified(
	unsigned char *signature_out,
	const unsigned char *m, size_t mlen,
	const unsigned char *sk, const unsigned char* pk,
	const unsigned char* random
)
{
	unsigned char nonce[64];
	unsigned char hram[64];
	unsigned char * sigbuf;

	SHA_512 sha;
	ge_p3 R;
	int count = 0;

	if ((sigbuf = (unsigned char*)malloc(mlen+128)) == 0) {
		memset(signature_out, 0, 64);
		return -1;
	}

	memmove(sigbuf + 64, m, mlen);
	memmove(sigbuf + 32, sk, 32);				
	sigbuf[0] = 0xFE;
	for (count = 1; count < 32; count++)
		sigbuf[count] = 0xFF;

	/* add suffix of random data */
	memmove(sigbuf + mlen + 64, random, 64);
	sha.update(sigbuf, mlen + 128);
	sha.final(nonce);
	memmove(sigbuf + 32, pk, 32);

	sc_reduce(nonce);
	ge_scalarmult_base(sigbuf, nonce);

	sha.update(sigbuf, mlen + 64);
	sha.final(hram);

	sc_reduce(hram);
	sc_muladd(sigbuf + 32, hram, sk, nonce);
	memmove(signature_out, sigbuf, 64);
	
	free(sigbuf);
	return 0;
}

int ed25519_verify_modified(
	const unsigned char *m, size_t mlen, const unsigned char *sig,
	const unsigned char *pk
)
{
	unsigned char pkcopy[32];
	unsigned char rcopy[32];
	unsigned char scopy[32];
	unsigned char h[64];
	unsigned char rcheck[32];
	unsigned char *verifybuf = NULL;
	ge_p3 A;
	ge_p2 R;

	std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-512"));
	int retvalue = 0;

	if (sig[63] & 224)
		goto exit;

	if (ge_frombytes_negate_vartime(&A, pk) != 0)
		goto exit;

	if ((verifybuf = (unsigned char*) malloc(mlen+64)) == 0) {
		goto exit;
	}

	memmove(pkcopy, pk, 32);
	memmove(rcopy, sig, 32);
	memmove(scopy, sig + 32, 32);
	memmove(verifybuf, sig, 64);
	memmove(verifybuf+64, m, mlen);
	memmove(verifybuf + 32, pkcopy, 32);

	hash->update(verifybuf, mlen+64);
	hash->final(h);

	sc_reduce(h);

	ge_double_scalarmult_vartime(rcheck, h, &A, scopy);

	if (constant_time_compare(rcheck, rcopy, 32)) {
		retvalue = 1;
	}

exit:
	if (verifybuf != NULL) {
		free(verifybuf);
	}

	return retvalue;
}


int curve25519_verify(const unsigned char* signature,
	const unsigned char* curve25519_pubkey,
	const unsigned char* msg, const size_t msg_len)
{
	fe u;
	fe y;
	unsigned char ed_pubkey[32];
	unsigned char loc_signature[64];
	int result;

	fe_frombytes(u, curve25519_pubkey);

	/* Convert montgomery x-coordinate  into an edwards y - coordinate:
	y = (u - 1) / (u + 1) */
	fe_montx_to_edy(&y, u); 
	fe_tobytes(ed_pubkey, y);

	ed_pubkey[31] &= 0x7F; 
	ed_pubkey[31] |= (signature[63] & 0x80);
	memmove(loc_signature, signature, 64);
	loc_signature[63] &= 0x7F;

	result = ed25519_verify_modified(msg, msg_len, loc_signature, ed_pubkey);

err:

	return result;
}

}
