/*************************************************
* Algorithm Lookup Header File                   *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_LOOKUP_H__
#define BOTAN_LOOKUP_H__

#include <botan/base.h>
#include <botan/filters.h>
#include <botan/mode_pad.h>
#include <botan/pk_util.h>
#include <botan/s2k.h>

namespace Botan {

/*************************************************
* Retrieve an object from the lookup table       *
*************************************************/
const BlockCipher*                  retrieve_block_cipher(const std::string&);
const StreamCipher*                 retrieve_stream_cipher(const std::string&);
const HashFunction*                 retrieve_hash(const std::string&);
const MessageAuthenticationCode*    retrieve_mac(const std::string&);
const S2K*                          retrieve_s2k(const std::string&);
const BlockCipherModePaddingMethod* retrieve_bc_pad(const std::string&);

/*************************************************
* Get an algorithm object                        *
*************************************************/
BlockCipher*                        get_block_cipher(const std::string&);
StreamCipher*                       get_stream_cipher(const std::string&);
HashFunction*                       get_hash(const std::string&);
MessageAuthenticationCode*          get_mac(const std::string&);
S2K*                                get_s2k(const std::string&);
const BlockCipherModePaddingMethod* get_bc_pad(const std::string&);

/*************************************************
* Get an EMSA/EME/KDF/MGF function               *
*************************************************/
EME*  get_eme(const std::string&);
EMSA* get_emsa(const std::string&);
MGF*  get_mgf(const std::string&);
KDF*  get_kdf(const std::string&);

/*************************************************
* Get a cipher object                            *
*************************************************/
Keyed_Filter* get_cipher(const std::string&, const SymmetricKey&,
                         const InitializationVector&, Cipher_Dir);
Keyed_Filter* get_cipher(const std::string&, const SymmetricKey&, Cipher_Dir);
Keyed_Filter* get_cipher(const std::string&, Cipher_Dir);

/*************************************************
* Check to see if an algorithm exists            *
*************************************************/
bool have_algorithm(const std::string&);

bool have_block_cipher(const std::string&);
bool have_stream_cipher(const std::string&);
bool have_hash(const std::string&);
bool have_mac(const std::string&);

/*************************************************
* Dereference an alias                           *
*************************************************/
std::string deref_alias(const std::string&);

/*************************************************
* Query information about an algorithm           *
*************************************************/
u32bit block_size_of(const std::string&);
u32bit output_length_of(const std::string&);

bool valid_keylength_for(u32bit, const std::string&);
u32bit min_keylength_of(const std::string&);
u32bit max_keylength_of(const std::string&);
u32bit keylength_multiple_of(const std::string&);

}

#endif
