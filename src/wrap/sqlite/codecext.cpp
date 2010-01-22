/*
 * SQLite3 encryption extention codec
 * (C) 2010 Olivier de Gaalon
 *
 * Distributed under the terms of the Botan license
 */

#ifndef SQLITE_OMIT_DISKIO
#ifdef SQLITE_HAS_CODEC

#include "codec.h"
#include "sqlite3.h"

// Required to implement, called from pragma.c, guessing that "see" is related to the
// "SQLite Encryption Extension" (the semi-official, for-pay, encryption codec)
extern "C"
void sqlite3_activate_see(const char *info) { }

// Free the encryption codec, called from pager.c (address passed in sqlite3PagerSetCodec)
extern "C"
void sqlite3PagerFreeCodec(void *pCodec)
{
    if (pCodec)
        delete (Codec*) pCodec;
}

// Report the page size to the codec, called from pager.c (address passed in sqlite3PagerSetCodec)
extern "C"
void sqlite3CodecSizeChange(void *pCodec, int pageSize, int nReserve)
{
    Codec* codec = (Codec*) pCodec;
    codec->SetPageSize(pageSize);
}

// Encrypt/Decrypt functionality, called by pager.c
extern "C"
void* sqlite3Codec(void* pCodec, void* data, Pgno nPageNum, int nMode)
{
    if (pCodec == NULL) //Db not encrypted
        return data;

    Codec* codec = (Codec*) pCodec;

    try
    {
        switch(nMode)
        {
        case 0: // Undo a "case 7" journal file encryption
        case 2: // Reload a page
        case 3: // Load a page
                if (codec->HasReadKey())
                    codec->Decrypt(nPageNum, (unsigned char*) data);
            break;
        case 6: // Encrypt a page for the main database file
            if (codec->HasWriteKey())
                data = codec->Encrypt(nPageNum, (unsigned char*) data, true);
            break;
        case 7: // Encrypt a page for the journal file
        /*
        *Under normal circumstances, the readkey is the same as the writekey.  However,
        *when the database is being rekeyed, the readkey is not the same as the writekey.
        *(The writekey is the "destination key" for the rekey operation and the readkey
        *is the key the db is currently encrypted with)
        *Therefore, for case 7, when the rollback is being written, always encrypt using
        *the database's readkey, which is guaranteed to be the same key that was used to
        *read and write the original data.
        */
            if (codec->HasReadKey())
                data = codec->Encrypt(nPageNum, (unsigned char*) data, false);
            break;
        }
    }
    catch(Botan::Exception e)
    {
        sqlite3Error((sqlite3*)codec->GetDB(), SQLITE_ERROR, "Botan Error: %s", e.what());
    }

    return data;
}

//These functions are defined in pager.c
extern "C" void* sqlite3PagerGetCodec(Pager *pPager);
extern "C" void sqlite3PagerSetCodec(
    Pager *pPager,
    void *(*xCodec)(void*,void*,Pgno,int),
    void (*xCodecSizeChng)(void*,int,int),
    void (*xCodecFree)(void*),
    void *pCodec
);


extern "C"
int sqlite3CodecAttach(sqlite3* db, int nDb, const void* zKey, int nKey)
{
    try {
        if (zKey == NULL || nKey <= 0)
        {
            // No key specified, could mean either use the main db's encryption or no encryption
            if (nDb != 0 && nKey < 0)
            {
                //Is an attached database, therefore use the key of main database, if main database is encrypted
                Codec* mainCodec = (Codec*) sqlite3PagerGetCodec(sqlite3BtreePager(db->aDb[0].pBt));
                if (mainCodec != NULL)
                {
                    Codec* codec = new Codec(*mainCodec, db);
                    sqlite3PagerSetCodec(sqlite3BtreePager(db->aDb[nDb].pBt),
                                        sqlite3Codec,
                                        sqlite3CodecSizeChange,
                                        sqlite3PagerFreeCodec, codec);
                }
            }
        }
        else
        {
            // Key specified, setup encryption key for database
            Codec* codec = new Codec(db);
            codec->GenerateWriteKey((const char*) zKey, nKey);
            codec->SetReadIsWrite();
            sqlite3PagerSetCodec(sqlite3BtreePager(db->aDb[nDb].pBt),
                                sqlite3Codec,
                                sqlite3CodecSizeChange,
                                sqlite3PagerFreeCodec, codec);
        }
    }
    catch(Botan::Exception e) {
        sqlite3Error(db, SQLITE_ERROR, "Botan Error: %s", e.what());
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

extern "C"
void sqlite3CodecGetKey(sqlite3* db, int nDb, void** zKey, int* nKey)
{
    // The unencrypted password is not stored for security reasons
    // therefore always return NULL
    *zKey = NULL;
    *nKey = -1;
}

extern "C"
int sqlite3_key(sqlite3 *db, const void *zKey, int nKey)
{
    // The key is only set for the main database, not the temp database
    return sqlite3CodecAttach(db, 0, zKey, nKey);
}

extern "C"
int sqlite3_rekey(sqlite3 *db, const void *zKey, int nKey)
{
    // Changes the encryption key for an existing database.
    int rc = SQLITE_ERROR;
    Btree* pbt = db->aDb[0].pBt;
    Pager* pPager = sqlite3BtreePager(pbt);
    Codec* codec = (Codec*) sqlite3PagerGetCodec(pPager);

    if ((zKey == NULL || nKey == 0) && codec == NULL)
    {
        // Database not encrypted and key not specified. Do nothing
        return SQLITE_OK;
    }

    if (codec == NULL)
    {
        // Database not encrypted, but key specified. Encrypt database
        try {
            codec = new Codec(db);
            codec->GenerateWriteKey((const char*) zKey, nKey);
        } catch (Botan::Exception e) {
            sqlite3Error(db, SQLITE_ERROR, "Botan Error %s", e.what());
            return SQLITE_ERROR;
        }
        sqlite3PagerSetCodec(pPager, sqlite3Codec, sqlite3CodecSizeChange, sqlite3PagerFreeCodec, codec);
    }
    else if (zKey == NULL || nKey == 0)
    {
        // Database encrypted, but key not specified. Decrypt database
        // Keep read key, drop write key
        codec->DropWriteKey();
    }
    else
    {
        // Database encrypted and key specified. Re-encrypt database with new key
        // Keep read key, change write key to new key
        try {
            codec->GenerateWriteKey((const char*) zKey, nKey);
        } catch (Botan::Exception e) {
            sqlite3Error(db, SQLITE_ERROR, "Botan Error %s", e.what());
            return SQLITE_ERROR;
        }
    }

    // Start transaction
    rc = sqlite3BtreeBeginTrans(pbt, 1);
    if (rc == SQLITE_OK)
    {
        // Rewrite all pages using the new encryption key (if specified)
        int nPageCount = -1;
        int rc = sqlite3PagerPagecount(pPager, &nPageCount);
        Pgno nPage = (Pgno) nPageCount;
        int pageSize = sqlite3BtreeGetPageSize(pbt);
        //Can't use SQLite3 macro here since pager is forward declared...sigh
        Pgno nSkip = CODEC_PAGER_MJ_PGNO(pageSize);
        DbPage *pPage;

        for (Pgno n = 1; rc == SQLITE_OK && n <= nPage; n++)
        {
            if (n == nSkip)
                continue;

            rc = sqlite3PagerGet(pPager, n, &pPage);

            if (!rc)
            {
                rc = sqlite3PagerWrite(pPage);
                sqlite3PagerUnref(pPage);
            }
            else
                sqlite3Error(db, SQLITE_ERROR, "%s", "Error while rekeying database page. Transaction Canceled.");
        }
    }
    else
        sqlite3Error(db, SQLITE_ERROR, "%s", "Error beginning rekey transaction. Make sure that the current encryption key is correct.");

    if (rc == SQLITE_OK)
    {
        // All good, commit
        rc = sqlite3BtreeCommit(pbt);

        if (rc == SQLITE_OK)
        {
            //Database rekeyed and committed successfully, update read key
            if (codec->HasWriteKey())
                codec->SetReadIsWrite();
            else //No write key == no longer encrypted
                sqlite3PagerSetCodec(pPager, NULL, NULL, NULL, NULL); 
        }
        else
        {
            //FIXME: can't trigger this, not sure if rollback is needed, reference implementation didn't rollback
            sqlite3Error(db, SQLITE_ERROR, "%s", "Could not commit rekey transaction.");
        }
    }
    else
    {
        // Rollback, rekey failed
        sqlite3BtreeRollback(pbt);

        // go back to read key
        if (codec->HasReadKey())
            codec->SetWriteIsRead();
        else //Database wasn't encrypted to start with
            sqlite3PagerSetCodec(pPager, NULL, NULL, NULL, NULL); 
    }

    return rc;
}

#endif // SQLITE_HAS_CODEC

#endif // SQLITE_OMIT_DISKIO
