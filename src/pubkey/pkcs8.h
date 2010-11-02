/*
* PKCS #8
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PKCS8_H__
#define BOTAN_PKCS8_H__

#include <botan/x509_key.h>
#include <botan/ui.h>

namespace Botan {

/**
* PKCS #8 General Exception
*/
struct BOTAN_DLL PKCS8_Exception : public Decoding_Error
   {
   PKCS8_Exception(const std::string& error) :
      Decoding_Error("PKCS #8: " + error) {}
   };

/**
* This namespace contains functions for handling PKCS #8 private keys
*/
namespace PKCS8 {

/**
* BER encode a private key
* @param key the private key to encode
* @return BER encoded key
*/
BOTAN_DLL SecureVector<byte> BER_encode(const Private_Key& key);

/**
* Get a string containing a PEM encoded private key.
* @param key the key to encode
* @return encoded key
*/
BOTAN_DLL std::string PEM_encode(const Private_Key& key);

/**
* Encrypt a key using PKCS #8 encryption
* @param key the key to encode
* @param rng the rng to use
* @param pass the password to use for encryption
* @param pbe_algo the name of the desired password-based encryption
         algorithm; if empty ("") a reasonable (portable/secure)
         default will be chosen.
* @return encrypted key in binary BER form
*/
BOTAN_DLL SecureVector<byte> BER_encode(const Private_Key& key,
                                        RandomNumberGenerator& rng,
                                        const std::string& pass,
                                        const std::string& pbe_algo = "");

/**
* Get a string containing a PEM encoded private key, encrypting it with a
* password.
* @param key the key to encode
* @param rng the rng to use
* @param pass the password to use for encryption
* @param pbe_algo the name of the desired password-based encryption
         algorithm; if empty ("") a reasonable (portable/secure)
         default will be chosen.
* @return encrypted key in PEM form
*/
BOTAN_DLL std::string PEM_encode(const Private_Key& key,
                                 RandomNumberGenerator& rng,
                                 const std::string& pass,
                                 const std::string& pbe_algo = "");


/**
* Encode a private key into a pipe.
* @deprecated Use PEM_encode or BER_encode instead
*
* @param key the private key to encode
* @param pipe the pipe to feed the encoded key into
* @param encoding the encoding type to use
*/
BOTAN_DEPRECATED("Use PEM_encode or BER_encode")
inline void encode(const Private_Key& key,
                   Pipe& pipe,
                   X509_Encoding encoding = PEM)
   {
   if(encoding == PEM)
      pipe.write(PKCS8::PEM_encode(key));
   else
      pipe.write(PKCS8::BER_encode(key));
   }

/**
* Encode and encrypt a private key into a pipe.
* @deprecated Use PEM_encode or BER_encode instead
*
* @param key the private key to encode
* @param pipe the pipe to feed the encoded key into
* @param pass the password to use for encryption
* @param rng the rng to use
* @param pbe_algo the name of the desired password-based encryption
         algorithm; if empty ("") a reasonable (portable/secure)
         default will be chosen.
* @param encoding the encoding type to use
*/
BOTAN_DEPRECATED("Use PEM_encode or BER_encode")
inline void encrypt_key(const Private_Key& key,
                        Pipe& pipe,
                        RandomNumberGenerator& rng,
                        const std::string& pass,
                        const std::string& pbe_algo = "",
                        X509_Encoding encoding = PEM)
   {
   if(encoding == PEM)
      pipe.write(PKCS8::PEM_encode(key, rng, pass, pbe_algo));
   else
      pipe.write(PKCS8::BER_encode(key, rng, pass, pbe_algo));
   }

/**
* Load a key from a data source.
* @param source the data source providing the encoded key
* @param rng the rng to use
* @param ui the user interface to be used for passphrase dialog
* @return loaded private key object
*/
BOTAN_DLL Private_Key* load_key(DataSource& source,
                                RandomNumberGenerator& rng,
                                const User_Interface& ui);

/** Load a key from a data source.
* @param source the data source providing the encoded key
* @param rng the rng to use
* @param pass the passphrase to decrypt the key. Provide an empty
* string if the key is not encoded.
* @return loaded private key object
*/
BOTAN_DLL Private_Key* load_key(DataSource& source,
                                RandomNumberGenerator& rng,
                                const std::string& pass = "");

/**
* Load a key from a file.
* @param filename the path to the file containing the encoded key
* @param rng the rng to use
* @param ui the user interface to be used for passphrase dialog
* @return loaded private key object
*/
BOTAN_DLL Private_Key* load_key(const std::string& filename,
                                RandomNumberGenerator& rng,
                                const User_Interface& ui);

/** Load a key from a file.
* @param filename the path to the file containing the encoded key
* @param rng the rng to use
* @param pass the passphrase to decrypt the key. Provide an empty
* string if the key is not encoded.
* @return loaded private key object
*/
BOTAN_DLL Private_Key* load_key(const std::string& filename,
                                RandomNumberGenerator& rng,
                                const std::string& pass = "");

/**
* Copy an existing encoded key object.
* @param key the key to copy
* @param rng the rng to use
* @return new copy of the key
*/
BOTAN_DLL Private_Key* copy_key(const Private_Key& key,
                                RandomNumberGenerator& rng);

}

}

#endif
