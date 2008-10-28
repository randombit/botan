/*************************************************
* Algorithm Lookup Header File                   *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_LOOKUP_H__
#define BOTAN_LOOKUP_H__

#include <botan/base.h>
#include <botan/enums.h>
#include <botan/filters.h>
#include <botan/mode_pad.h>
#include <botan/kdf.h>
#include <botan/pk_pad.h>
#include <botan/libstate.h>
#include <botan/s2k.h>

namespace Botan {

/*************************************************
* Retrieve an object from the lookup table       *
*************************************************/
// NOTE: these functions return internally stored objects, library
// retains ownership

BOTAN_DLL const BlockCipher*
retrieve_block_cipher(Library_State&, const std::string&);

BOTAN_DLL const StreamCipher*
retrieve_stream_cipher(Library_State&, const std::string&);

BOTAN_DLL const HashFunction*
retrieve_hash(Library_State&, const std::string&);

BOTAN_DLL const MessageAuthenticationCode*
retrieve_mac(Library_State&, const std::string&);

BOTAN_DLL const S2K* retrieve_s2k(Library_State&, const std::string&);

BOTAN_DLL const BlockCipherModePaddingMethod*
retrieve_bc_pad(Library_State&, const std::string&);

/*************************************************
* Get an algorithm object                        *
*************************************************/
// NOTE: these functions create and return new objects, letting the
// caller assume ownership of them

/**
* Block cipher factory method.
* @param name the name of the desired block cipher
* @return the block cipher object
*/
BOTAN_DLL BlockCipher* get_block_cipher(const std::string& name);


/**
* Stream cipher factory method.
* @param name the name of the desired stream cipher
* @return the stream cipher object
*/
BOTAN_DLL StreamCipher* get_stream_cipher(const std::string& name);

/**
* Hash function factory method.
* @param name the name of the desired hash function
* @return the hash function object
*/
BOTAN_DLL HashFunction* get_hash(const std::string& name);

/**
* MAC factory method.
* @param name the name of the desired MAC
* @return the MAC object
*/
BOTAN_DLL MessageAuthenticationCode* get_mac(const std::string& name);

/**
* String to key algorithm factory method.
* @param name the name of the desired string to key (S2K) algorithm
* @return the string to key algorithm object
*/
BOTAN_DLL S2K* get_s2k(const std::string& name);

/**
* Block cipher padding mode factory/retrieval method.
* @param name the name of the desired block cipher padding mode
* @return the block cipher padding mode object
*/
BOTAN_DLL const BlockCipherModePaddingMethod*
   get_bc_pad(const std::string& name);

/*************************************************
* Get an EMSA/EME/KDF/MGF function               *
*************************************************/
// NOTE: these functions create and return new objects, letting the
// caller assume ownership of them

/**
* Factory method for EME (message-encoding methods for encryption) objects
* @param name the name of the EME to create
* @return the desired EME object
*/
BOTAN_DLL EME*  get_eme(const std::string& name);

/**
* Factory method for EMSA (message-encoding methods for signatures
* with appendix) objects
* @param name the name of the EME to create
* @return the desired EME object
*/
BOTAN_DLL EMSA* get_emsa(const std::string& name);

/**
* Factory method for MGF (mask generation function)
* @param name the name of the MGF to create
* @return the desired MGF object
*/
BOTAN_DLL MGF*  get_mgf(const std::string& name);

/**
* Factory method for KDF (key derivation function)
* @param name the name of the KDF to create
* @return the desired KDF object
*/
BOTAN_DLL KDF*  get_kdf(const std::string& name);

/*************************************************
* Get a cipher object                            *
*************************************************/

/**
* Factory method for general symmetric cipher filters.
* @param name the name of the desired cipher
* @param key the key to be used for encryption/decryption performed by
* the filter
* @param iv the initialization vector to be used
* @param dir determines whether the filter will be an encrypting or decrypting
* filter
* @return the encryption or decryption filter
*/
BOTAN_DLL Keyed_Filter* get_cipher(const std::string& name,
                                   const SymmetricKey& key,
                                   const InitializationVector& iv,
                                   Cipher_Dir dir);
/**
* Factory method for general symmetric cipher filters.
* @param name the name of the desired cipher
* @param key the key to be used for encryption/decryption performed by
* the filter
* @param dir determines whether the filter will be an encrypting or decrypting
* filter
* @return the encryption or decryption filter
*/
BOTAN_DLL Keyed_Filter* get_cipher(const std::string& name,
                                   const SymmetricKey& key,
                                   Cipher_Dir dir);

/** Factory method for general symmetric cipher filters. No key will
* be set in the filter.
* @param name the name of the desired cipher

* @param dir determines whether the filter will be an encrypting or
* decrypting filter
* @return the encryption or decryption filter
*/
BOTAN_DLL Keyed_Filter* get_cipher(const std::string& name, Cipher_Dir dir);

/**
* Check if an algorithm exists.
* @param name the name of the algorithm to check for
* @return true if the algorithm exists, false otherwise
*/
BOTAN_DLL bool have_algorithm(const std::string& name);

/**
* Check if a block cipher algorithm exists.
* @param name the name of the algorithm to check for
* @return true if the algorithm exists, false otherwise
*/
BOTAN_DLL bool have_block_cipher(const std::string& name);

/**
* Check if a stream cipher algorithm exists.
* @param name the name of the algorithm to check for
* @return true if the algorithm exists, false otherwise
*/
BOTAN_DLL bool have_stream_cipher(const std::string& name);

/**
* Check if a hash algorithm exists.
* @param name the name of the algorithm to check for
* @return true if the algorithm exists, false otherwise
*/
BOTAN_DLL bool have_hash(const std::string& name);

/**
* Check if a MAC algorithm exists.
* @param name the name of the algorithm to check for
* @return true if the algorithm exists, false otherwise
*/
BOTAN_DLL bool have_mac(const std::string& name);

/*************************************************
* Query information about an algorithm           *
*************************************************/

/**
* Find out the block size of a certain symmetric algorithm.
* @param name the name of the algorithm
* @return the block size of the specified algorithm
*/
BOTAN_DLL u32bit block_size_of(const std::string& name);

/**
* Find out the output length of a certain symmetric algorithm.
* @param name the name of the algorithm
* @return the output length of the specified algorithm
*/
BOTAN_DLL u32bit output_length_of(const std::string& name);

/**
* Find out the whether a certain key length is allowd for a given
* symmetric algorithm.
* @param keylen the key length in question
* @param name the name of the algorithm
* @return true if the key length is valid for that algorithm, false otherwise
*/
BOTAN_DLL bool valid_keylength_for(u32bit keylen, const std::string& name);

/**
* Find out the minimum key size of a certain symmetric algorithm.
* @param name the name of the algorithm
* @return the minimum key length of the specified algorithm
*/
BOTAN_DLL u32bit min_keylength_of(const std::string& name);

/**
* Find out the maximum key size of a certain symmetric algorithm.
* @param name the name of the algorithm
* @return the maximum key length of the specified algorithm
*/
BOTAN_DLL u32bit max_keylength_of(const std::string& name);

/**
* Find out the size any valid key is a multiple of for a certain algorithm.
* @param name the name of the algorithm
* @return the size any valid key is a multiple of
*/
BOTAN_DLL u32bit keylength_multiple_of(const std::string& name);

}

#endif
