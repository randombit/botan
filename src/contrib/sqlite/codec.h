/*
 * Codec class for SQLite3 encryption codec.
 * (C) 2010 Olivier de Gaalon
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef _CODEC_H_
#define _CODEC_H_

#include <string>
#include <botan/botan.h>
#include <botan/loadstor.h>

using namespace std;
using namespace Botan;

/*These constants can be used to tweak the codec behavior as follows
 *Note that once you've encrypted a database with these settings,
 *recompiling with any different settings will give you a library that
 *cannot read that database, even given the same passphrase.*/

//BLOCK_CIPHER_STR: Cipher and mode used for encrypting the database
//make sure to add "/NoPadding" for modes that use padding schemes
const string BLOCK_CIPHER_STR = "Twofish/XTS";

//PBKDF_STR: Key derivation function used to derive both the encryption
//and IV derivation keys from the given database passphrase
const string PBKDF_STR = "PBKDF2(SHA-160)";

//SALT_STR: Hard coded salt used to derive the key from the passphrase.
const string SALT_STR = "&g#nB'9]";

//SALT_SIZE: Size of the salt in bytes (as given in SALT_STR)
const int SALT_SIZE = 64/8; //64 bit, 8 byte salt

//MAC_STR: CMAC used to derive the IV that is used for db page
//encryption
const string MAC_STR = "CMAC(Twofish)";

//PBKDF_ITERATIONS: Number of hash iterations used in the key derivation
//process.
const int PBKDF_ITERATIONS = 10000;

//KEY_SIZE: Size of the encryption key. Note that XTS splits the key
//between two ciphers, so if you're using XTS, double the intended key
//size. (ie, "AES-128/XTS" should have a 256 bit KEY_SIZE)
const int KEY_SIZE = 512/8; //512 bit, 64 byte key. (256 bit XTS key)

//IV_DERIVATION_KEY_SIZE: Size of the key used with the CMAC (MAC_STR)
//above.
const int IV_DERIVATION_KEY_SIZE = 256/8; //256 bit, 32 byte key

//This is definited in sqlite.h and very unlikely to change
#define SQLITE_MAX_PAGE_SIZE 32768

class Codec
{
public:
    Codec(void *db);
    Codec(const Codec* other, void *db);

    void GenerateWriteKey(const char *userPassword, int passwordLength);
    void DropWriteKey();
    void SetWriteIsRead();
    void SetReadIsWrite();

    unsigned char* Encrypt(int page, unsigned char *data, bool useWriteKey);
    void Decrypt(int page, unsigned char *data);

    void SetPageSize(int pageSize) { m_pageSize = pageSize; }

    bool HasReadKey() { return m_hasReadKey; }
    bool HasWriteKey() { return m_hasWriteKey; }
    void* GetDB() { return m_db; }
    const char* GetAndResetError();

private:
    bool m_hasReadKey;
    bool m_hasWriteKey;

    SymmetricKey
        m_readKey,
        m_writeKey,
        m_ivReadKey,
        m_ivWriteKey;

    Pipe
        m_encipherPipe,
        m_decipherPipe,
        m_macPipe;

    Keyed_Filter *m_encipherFilter;
    Keyed_Filter *m_decipherFilter;
    MAC_Filter *m_cmac;

    int m_pageSize;
    unsigned char m_page[SQLITE_MAX_PAGE_SIZE];
    void *m_db;
    const char *m_botanErrorMsg;

    InitializationVector GetIVForPage(u32bit page, bool useWriteKey);
    void InitializeCodec(void *db);
};

#endif
