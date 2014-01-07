/*
 * Codec class for SQLite3 encryption codec.
 * (C) 2010 Olivier de Gaalon
 *
 * Distributed under the terms of the Botan license
 */

#include "codec.h"
#include <botan/init.h>

Codec::Codec(void *db)
{
    InitializeCodec(db);
}

Codec::Codec(const Codec *other, void *db)
{
    //Only used to copy main db key for an attached db
    InitializeCodec(db);
    m_hasReadKey = other->m_hasReadKey;
    m_hasWriteKey = other->m_hasWriteKey;
    m_readKey = other->m_readKey;
    m_ivReadKey = other->m_ivReadKey;
    m_writeKey = other->m_writeKey;
    m_ivWriteKey = other->m_ivWriteKey;
}

void Codec::InitializeCodec(void *db)
{
    m_hasReadKey  = false;
    m_hasWriteKey = false;
    m_db = db;

    try
    {
        m_encipherFilter = get_cipher(BLOCK_CIPHER_STR, ENCRYPTION);
        m_decipherFilter = get_cipher(BLOCK_CIPHER_STR, DECRYPTION);
        m_cmac = new MAC_Filter(MAC_STR);
        m_encipherPipe.append(m_encipherFilter);
        m_decipherPipe.append(m_decipherFilter);
        m_macPipe.append(m_cmac);
    }
    catch(Botan::Exception e)
    {
        m_botanErrorMsg = e.what();
    }
}

void Codec::GenerateWriteKey(const char *userPassword, int passwordLength)
{
    try
    {
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,9,4)
        PBKDF *pbkdf = get_pbkdf(PBKDF_STR);
        SymmetricKey masterKey =
            pbkdf->derive_key(KEY_SIZE + IV_DERIVATION_KEY_SIZE, std::string(userPassword, passwordLength),
                              (const byte*)SALT_STR.c_str(), SALT_SIZE, PBKDF_ITERATIONS);
#elif BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,8,0)
        S2K* s2k = get_s2k(PBKDF_STR);
        s2k->set_iterations(PBKDF_ITERATIONS);
        s2k->change_salt((const byte*)SALT_STR.c_str(), SALT_SIZE);

        SymmetricKey masterKey =
            s2k->derive_key(KEY_SIZE + IV_DERIVATION_KEY_SIZE, std::string(userPassword, passwordLength));
#else
#error "This code requires botan 1.8 or newer"
#endif
        m_writeKey = SymmetricKey(masterKey.bits_of(), KEY_SIZE);
        m_ivWriteKey = SymmetricKey(masterKey.bits_of() + KEY_SIZE, IV_DERIVATION_KEY_SIZE);

        m_hasWriteKey = true;
    }
    catch(Botan::Exception e)
    {
        m_botanErrorMsg = e.what();
    }
}

void Codec::DropWriteKey()
{
    m_hasWriteKey = false;
}

void Codec::SetReadIsWrite()
{
    m_readKey = m_writeKey;
    m_ivReadKey = m_ivWriteKey;
    m_hasReadKey = m_hasWriteKey;
}

void Codec::SetWriteIsRead()
{
    m_writeKey = m_readKey;
    m_ivWriteKey = m_ivReadKey;
    m_hasWriteKey = m_hasReadKey;
}

unsigned char* Codec::Encrypt(int page, unsigned char *data, bool useWriteKey)
{
    memcpy(m_page, data, m_pageSize);

    try
    {
        m_encipherFilter->set_key(useWriteKey ? m_writeKey : m_readKey);
        m_encipherFilter->set_iv(GetIVForPage(page, useWriteKey));
        m_encipherPipe.process_msg(m_page, m_pageSize);
        m_encipherPipe.read(m_page, m_encipherPipe.remaining(Pipe::LAST_MESSAGE), Pipe::LAST_MESSAGE);
    }
    catch(Botan::Exception e)
    {
        m_botanErrorMsg = e.what();
    }

    return m_page; //return location of newly ciphered data
}

void Codec::Decrypt(int page, unsigned char *data)
{
    try
    {
        m_decipherFilter->set_key(m_readKey);
        m_decipherFilter->set_iv(GetIVForPage(page, false));
        m_decipherPipe.process_msg(data, m_pageSize);
        m_decipherPipe.read(data, m_decipherPipe.remaining(Pipe::LAST_MESSAGE), Pipe::LAST_MESSAGE);
    }
    catch(Botan::Exception e)
    {
        m_botanErrorMsg = e.what();
    }
}

InitializationVector Codec::GetIVForPage(u32bit page, bool useWriteKey)
{
    try
    {
        static unsigned char *intiv[4];
        store_le(page, (byte*)intiv);
        m_cmac->set_key(useWriteKey ? m_ivWriteKey : m_ivReadKey);
        m_macPipe.process_msg((byte*)intiv, 4);
        return m_macPipe.read_all(Pipe::LAST_MESSAGE);
    }
    catch(Botan::Exception e)
    {
        m_botanErrorMsg = e.what();
    }
}

const char* Codec::GetAndResetError()
{
    const char *message = m_botanErrorMsg;
    m_botanErrorMsg = 0;
    return message;
}

#include "codec_c_interface.h"

void InitializeBotan() {
    LibraryInitializer::initialize();
}
void* InitializeNewCodec(void *db) {
    return new Codec(db);
}
void* InitializeFromOtherCodec(const void *otherCodec, void *db) {
    return new Codec((Codec*)otherCodec, db);
}
void GenerateWriteKey(void *codec, const char *userPassword, int passwordLength) {
    ((Codec*)codec)->GenerateWriteKey(userPassword, passwordLength);
}
void DropWriteKey(void *codec) {
    ((Codec*)codec)->DropWriteKey();
}
void SetWriteIsRead(void *codec) {
    ((Codec*)codec)->SetWriteIsRead();
}
void SetReadIsWrite(void *codec) {
    ((Codec*)codec)->SetReadIsWrite();
}
unsigned char* Encrypt(void *codec, int page, unsigned char *data, Bool useWriteKey) {
    return ((Codec*)codec)->Encrypt(page, data, useWriteKey);
}
void Decrypt(void *codec, int page, unsigned char *data) {
    ((Codec*)codec)->Decrypt(page, data);
}
void SetPageSize(void *codec, int pageSize) {
    ((Codec*)codec)->SetPageSize(pageSize);
}
Bool HasReadKey(void *codec) {
    return ((Codec*)codec)->HasReadKey();
}
Bool HasWriteKey(void *codec) {
    return ((Codec*)codec)->HasWriteKey();
}
void* GetDB(void *codec) {
    return ((Codec*)codec)->GetDB();
}
const char* GetAndResetError(void *codec)
{
    return ((Codec*)codec)->GetAndResetError();
}
void DeleteCodec(void *codec) {
    Codec *deleteThisCodec = (Codec*)codec;
    delete deleteThisCodec;
}
