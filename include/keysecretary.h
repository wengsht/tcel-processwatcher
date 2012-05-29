

#ifndef TCEL_KEYSECRETARY_H
#define TCEL_KEYSECRETARY_H 1

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

typedef uint16_t UINT16;
typedef uint8_t BYTE;

/*
 * store key file of the file secretary
 * NOTE: MUST start wiht '/' and the reall path start from HOME NOT ROOT dir
 *
 */
#define TCEL_KEYSECRETARY_FILE_PATH "/TCEL_keysecretary.keys"
#define TCEL_KEYSECRETARY_PATH_BUF_SIZE 1024

#define TCEL_KEYSECRETARY_TYPE_MEM 		0
#define TCEL_KEYSECRETARY_TYPE_FILE		1
#define TCEL_KEYSECRETARY_TYPE_UDISK	2
#define TCEL_KEYSECRETARY_TYPE_SIZE		3


#define TCEL_KEYSECRETARY_TYPE_DEFAULT 	TCEL_KEYSECRETARY_TYPE_FILE
#define TCEL_KEYSECRETARY_FLAGS_DEFAULT 0

/*
 * TODO:add real udisk key secretary
 *
 */
#if TCEL_KEYSECRETARY_TYPE_DEFAULT != TCEL_KEYSECRETARY_TYPE_UDISK
	/* no udisk module then default the pointer to NULL */
#define __udiskKeyReader 	NULL
#define __udiskKeyWriter 	NULL
#define __udiskKeyCleaner	NULL

#else
int __udiskKeyReader(int a_type,int a_flags,UINT16 *p_blobLen,BYTE *keyBlob);
int  __udiskKeyWriter(int a_type,int a_flags,UINT16 a_blobLen,BYTE *keyBlob);
int  __udiskKeyCleaner();
#endif

struct KeySecretary {
	int   _type;
	int (*ReadKey)(int a_keyType,int a_flags,UINT16 *p_keyLen,BYTE *keyBlob);
	int (*WriteKey)(int a_keyType,int a_flags,UINT16 a_keyLen,BYTE *keyBlob);
	int (*CleanKey)();
};

void KeySecretary_Init(struct KeySecretary *p_Secretary,int a_type);

#endif
