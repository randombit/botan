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
// NOTE: these functions return internally stored objects, so we use shared_ptr here
std::tr1::shared_ptr<BlockCipher const>                  retrieve_block_cipher(const std::string&);
std::tr1::shared_ptr<StreamCipher const>                 retrieve_stream_cipher(const std::string&);
std::tr1::shared_ptr<HashFunction const>                 retrieve_hash(const std::string&);
std::tr1::shared_ptr<MessageAuthenticationCode const>    retrieve_mac(const std::string&);
std::tr1::shared_ptr<S2K const>                          retrieve_s2k(const std::string&);
std::tr1::shared_ptr<BlockCipherModePaddingMethod const> retrieve_bc_pad(const std::string&);

/*************************************************
* Get an algorithm object                        *
*************************************************/
// NOTE: these functions create and return new objects, letting the caller assume ownership of them
std::auto_ptr<BlockCipher>                               get_block_cipher(const std::string&);
std::auto_ptr<StreamCipher>                              get_stream_cipher(const std::string&);
std::auto_ptr<HashFunction>                              get_hash(const std::string&);
std::auto_ptr<MessageAuthenticationCode>                 get_mac(const std::string&);
std::auto_ptr<S2K>                                       get_s2k(const std::string&);
// NOTE: BlockCipherModePaddingMethod is not cloned
std::tr1::shared_ptr<BlockCipherModePaddingMethod const> get_bc_pad(const std::string&);

/*************************************************
* Get an EMSA/EME/KDF/MGF function               *
*************************************************/
// NOTE: these functions create and return new objects, letting the caller assume ownership of them
std::auto_ptr<EME>  get_eme(const std::string&);
std::auto_ptr<EMSA> get_emsa(const std::string&);
std::auto_ptr<MGF>  get_mgf(const std::string&);
std::auto_ptr<KDF>  get_kdf(const std::string&);

/*************************************************
* Get a cipher object                            *
*************************************************/
// NOTE: these functions return internally stored objects, so we use shared_ptr here
std::tr1::shared_ptr<Keyed_Filter> get_cipher(const std::string&, const SymmetricKey&,
                         const InitializationVector&, Cipher_Dir);
std::tr1::shared_ptr<Keyed_Filter> get_cipher(const std::string&, const SymmetricKey&, Cipher_Dir);
std::tr1::shared_ptr<Keyed_Filter> get_cipher(const std::string&, Cipher_Dir);

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
