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

Codec::Codec(const Codec& other, void *db)
{
    //Only used to copy main db key for an attached db
    InitializeCodec(db);
    m_hasReadKey = other.m_hasReadKey;
    m_hasWriteKey = other.m_hasWriteKey;
    m_readKey = other.m_readKey;
    m_ivReadKey = other.m_ivReadKey;
    m_writeKey = other.m_writeKey;
    m_ivWriteKey = other.m_ivWriteKey;
}

void
Codec::InitializeCodec(void *db)
{
    bool botanInitialized = false;
    Library_State* state = swap_global_state(0);
    if(state)
    {
        botanInitialized = true;
        swap_global_state(state); // should return NULL FIXME: what if not?
    }

    if (!botanInitialized)
        LibraryInitializer::initialize();

    m_hasReadKey  = false;
    m_hasWriteKey = false;
    m_db = db;

    m_encipherFilter = get_cipher(BLOCK_CIPHER_STR, ENCRYPTION);
    m_decipherFilter = get_cipher(BLOCK_CIPHER_STR, DECRYPTION);
    m_cmac = new MAC_Filter(MAC_STR);
    m_encipherPipe.append(m_encipherFilter);
    m_decipherPipe.append(m_decipherFilter);
    m_macPipe.append(m_cmac);
}

void
Codec::GenerateWriteKey(const char* userPassword, int passwordLength)
{
    S2K* s2k = get_s2k(S2K_STR);
    s2k->set_iterations(S2K_ITERATIONS);
    s2k->change_salt((const byte*)SALT_STR.c_str(), SALT_SIZE);

    SymmetricKey masterKey =
        s2k->derive_key(KEY_SIZE + IV_DERIVATION_KEY_SIZE, std::string(userPassword, passwordLength));

    m_writeKey = SymmetricKey(masterKey.bits_of(), KEY_SIZE);
    m_ivWriteKey = SymmetricKey(masterKey.bits_of() + KEY_SIZE, IV_DERIVATION_KEY_SIZE);

    m_hasWriteKey = true;
}

void
Codec::DropWriteKey()
{
    m_hasWriteKey = false;
}

void
Codec::SetReadIsWrite()
{
    m_readKey = m_writeKey;
    m_ivReadKey = m_ivWriteKey;
    m_hasReadKey = m_hasWriteKey;
}

void
Codec::SetWriteIsRead()
{
    m_writeKey = m_readKey;
    m_ivWriteKey = m_ivReadKey;
    m_hasWriteKey = m_hasReadKey;
}

unsigned char *
Codec::Encrypt(int page, unsigned char* data, bool useWriteKey)
{
    memcpy(m_page, data, m_pageSize);

    m_encipherFilter->set_key(useWriteKey ? m_writeKey : m_readKey);
    m_encipherFilter->set_iv(GetIVForPage(page, useWriteKey));
    m_encipherPipe.process_msg(m_page, m_pageSize);
    m_encipherPipe.read(m_page, m_encipherPipe.remaining(Pipe::LAST_MESSAGE), Pipe::LAST_MESSAGE);

    return m_page; //return location of newly ciphered data
}

void
Codec::Decrypt(int page, unsigned char* data)
{
    m_decipherFilter->set_key(m_readKey);
    m_decipherFilter->set_iv(GetIVForPage(page, false));
    m_decipherPipe.process_msg(data, m_pageSize);
    m_decipherPipe.read(data, m_decipherPipe.remaining(Pipe::LAST_MESSAGE), Pipe::LAST_MESSAGE);
}

InitializationVector
Codec::GetIVForPage(u32bit page, bool useWriteKey)
{
    static unsigned char* intiv[4];
    store_le(page, (byte*)intiv);
    m_cmac->set_key(useWriteKey ? m_ivWriteKey : m_ivReadKey);
    m_macPipe.process_msg((byte*)intiv, 4);
    return m_macPipe.read_all(Pipe::LAST_MESSAGE);
}

