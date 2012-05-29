#ifndef TCEL_CRYPTOMAN_H
#define TCEL_CRYPTOMAN_H 1

#include "cryptoman_tpm_utils.h"
#include "keysecretary.h"
#include <syslog.h>

#define TCEL_CRYPTOMAN_HASH_SIZE 			20
#define TCEL_CRYPTOMAN_SIGN_SIZE 			256
#define TCEL_CRYPTOMAN_BIND_SIZE			256
#define TCEL_CRYPTOMAN_KEY_SYMMETRIC_SIZE 	32

#define TCEL_CRYPTOMAN_KEY_BLOB_SIZE		1024 /* PS: test for tpm key blob size is 559 */
#define TCEL_CRYPTOMAN_KEY_USER_UUID_BASE	{1,2,3,4,5,{6,7,8,9,10,0}}

enum Cryptoman_Context_Type {
	Empty = 0,
	LoginGuard,
	ProcessWatcher,
	FileKeeper
};

struct Cryptoman_Context {
	enum Cryptoman_Context_Type  _type;
	TSS_HCONTEXT _hContext;
	TSS_UUID _uuid;
	TSS_HKEY _hAuthKey;
	TSS_HKEY _hSrk;
	TSS_HKEY _hKey;
};

TSS_RESULT
Cryptoman_SetupUserSecret(UINT32 a_userId,UINT32 a_authLen,BYTE *p_auth);

TSS_RESULT
Cryptoman_CleanupUserSecret(UINT32 a_userId);


TSS_RESULT 
Cryptoman_CreateContext(struct Cryptoman_Context *p_Context,
		enum Cryptoman_Context_Type a_type,
		UINT32 a_userId,UINT32 a_authLen,BYTE *p_auth);

TSS_RESULT
Cryptoman_CloseContext(struct Cryptoman_Context *p_Context);

TSS_RESULT
Cryptoman_MakeHash(struct Cryptoman_Context *p_Context,
		UINT32 a_dataLen,BYTE *p_data,
		UINT32 *p_hashLen,BYTE *p_hash);

/* for ProcessWatcher and LoginGuard */
TSS_RESULT
Cryptoman_MakeSign(struct Cryptoman_Context *p_Context,
		UINT32 a_hashLen,BYTE * p_hash,
		UINT32 *p_signLen,BYTE * p_sign);

TSS_RESULT
Cryptoman_VerifySign(struct Cryptoman_Context *p_Context,
		UINT32 a_hashLen,BYTE * p_hash,
		UINT32 a_signLen,BYTE * p_sign);

/* for FileKeeper */
TSS_RESULT
Cryptoman_BindSecret(struct Cryptoman_Context *p_Context,
		UINT32 a_dataLen,BYTE *p_data,
		UINT32 *p_bindLen,BYTE *p_bind);

TSS_RESULT
Cryptoman_UnbindSecret(struct Cryptoman_Context *p_Context,
		UINT32 a_unbindLen,BYTE *p_unbind,
		UINT32 *p_dataLen,BYTE *p_data);

TSS_RESULT
Cryptoman_MakeMasterKey(struct Cryptoman_Context *p_Context,
		UINT32 a_keyLen,BYTE *p_key);


#endif
