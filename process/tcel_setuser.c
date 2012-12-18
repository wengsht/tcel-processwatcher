
#include "cryptoman.h"
#include <stdio.h>
#include <stdlib.h>

/*static BYTE auth[] = "123456";*/
/*static UINT32 authLen = 6;*/

int main(int argc,char **argv)
{
	UINT32  userId = 0;
	if ( 3 != argc ){
		printf("Usage: %s <userId> <passwd>\n",argv[0]);
		return 1;
	}

	userId = atoi(argv[1]);
	BYTE* passwd = argv[2];

	assert(userId >= 0 && userId <= 10000);
    Cryptoman_CleanupUserSecret(userId);
	assert(TSS_SUCCESS == Cryptoman_SetupUserSecret(userId,
				strlen(passwd),passwd));

	return 0;
}
