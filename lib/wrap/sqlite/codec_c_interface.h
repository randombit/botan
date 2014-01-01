/*
 * Encryption codec class C interface
 * (C) 2010 Olivier de Gaalon
 *
 * Distributed under the terms of the Botan license
 */

#ifndef _CODEC_C_INTERFACE_H_
#define _CODEC_C_INTERFACE_H_

#ifdef __cplusplus
typedef unsigned char Bool;
#endif

#ifdef __cplusplus
extern "C"
#endif
void InitializeBotan();

#ifdef __cplusplus
extern "C"
#endif
void* InitializeNewCodec(void *db);

#ifdef __cplusplus
extern "C"
#endif
void* InitializeFromOtherCodec(const void *otherCodec, void *db);

#ifdef __cplusplus
extern "C"
#endif
void GenerateWriteKey(void *codec, const char *userPassword, int passwordLength);

#ifdef __cplusplus
extern "C"
#endif
void DropWriteKey(void *codec);

#ifdef __cplusplus
extern "C"
#endif
void SetWriteIsRead(void *codec);

#ifdef __cplusplus
extern "C"
#endif
void SetReadIsWrite(void *codec);

#ifdef __cplusplus
extern "C"
#endif
unsigned char* Encrypt(void *codec, int page, unsigned char *data, Bool useWriteKey);

#ifdef __cplusplus
extern "C"
#endif
void Decrypt(void *codec, int page, unsigned char *data);

#ifdef __cplusplus
extern "C"
#endif
void SetPageSize(void *codec, int pageSize);

#ifdef __cplusplus
extern "C"
#endif
Bool HasReadKey(void *codec);

#ifdef __cplusplus
extern "C"
#endif
Bool HasWriteKey(void *codec);

#ifdef __cplusplus
extern "C"
#endif
void* GetDB(void *codec);

#ifdef __cplusplus
extern "C"
#endif
const char* GetAndResetError(void *codec);

#ifdef __cplusplus
extern "C"
#endif
void DeleteCodec(void *codec);

#endif