#ifndef TCEL_CRYPTOMAN_TPM_UTILS_H
#define TCEL_CRYPTOMAN_TPM_UTILS_H 

#include "tpm_utils.h"
#include "tpm_tspi.h"
#include "stdio.h"

#define TCEL_KEY_SYMMETRIC_SIZE	32 /* 32*8=256 */	

TSS_RESULT __createTpmKey(TSS_HCONTEXT a_hContext,TSS_HKEY *p_hKey,
		TSS_FLAG a_keyType,UINT32 a_lenSecret,BYTE *p_secret,
		TSS_HKEY a_phKey);

TSS_RESULT __loadTpmSrk(TSS_HCONTEXT a_hContext,TSS_HKEY *p_hSrk);

TSS_RESULT __createTpmKey(TSS_HCONTEXT a_hContext,TSS_HKEY *p_hKey,
		TSS_FLAG a_keyType,UINT32 a_lenSecret,BYTE *p_secret,
		TSS_HKEY a_phKey);

TSS_RESULT __createAuthKey(TSS_HCONTEXT a_hContext,TSS_HKEY *p_hKey,
		TSS_UUID a_uuid,
		UINT32 a_lenSecret,BYTE *p_secret, TSS_HKEY a_phKey);

TSS_RESULT __saveTpmKey(TSS_HKEY a_hKey,
		UINT32 *p_keyBlobLen,BYTE **pp_keyBlob);

TSS_RESULT __loadTpmKey(TSS_HCONTEXT a_hContext,TSS_HKEY *p_hKey,
		UINT32 a_keyBlobLen,BYTE *p_keyBlob,TSS_HKEY a_phKey);

TSS_RESULT __loadTpmAuthKey(TSS_HCONTEXT a_hContext,TSS_HKEY *p_hKey,
		TSS_UUID a_uuid,UINT32 a_authLen,BYTE *p_auth);

TSS_RESULT __dataHash(TSS_HCONTEXT a_hContext,UINT32 a_dataLen,BYTE *data,
		UINT32 *p_hashLen,BYTE **pp_hash);

TSS_RESULT __hashSign(TSS_HCONTEXT a_hContext,UINT32 a_hashLen,BYTE p_hash[20],
		UINT32 *p_signLen,BYTE **pp_sign,TSS_HKEY a_hKey);

TSS_RESULT __hashVerifySign(TSS_HCONTEXT a_hContext,UINT32 a_hashLen,BYTE p_hash[20],
		UINT32 a_signLen,BYTE *p_sign,TSS_HKEY a_hKey);

TSS_RESULT __dataBind(TSS_HCONTEXT a_hContext,UINT32 a_dataLen,BYTE *p_data,
		UINT32 *p_blobLen,BYTE **pp_blob,TSS_HKEY a_hKey);

TSS_RESULT __dataUnbind(TSS_HCONTEXT a_hContext,UINT32 a_dataLen,BYTE *p_data,
		UINT32 *p_blobLen,BYTE **pp_blob,TSS_HKEY a_hKey);

TSS_RESULT __getRandom(TSS_HCONTEXT a_hContext,UINT32 a_randLen,
		BYTE **pp_rand);
#endif
