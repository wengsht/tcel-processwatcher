#ifndef IMA_READER_H
#define IMA_READER_H

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <glib.h>

#define IMA_RECOMPILED
#define PROCESS_MAX_NUM 20000    /* 最多进程个数 */
#define PROCESS_PATH_MAX_LEN 1024 /*  最长绝对路径名 */
#define TCG_EVENT_NAME_LEN_MAX  255
struct Event 
{
    struct 
    {
        u_int32_t pcr;
        u_int8_t digest[SHA_DIGEST_LENGTH];
        u_int32_t name_len;
    } header;
    char name[TCG_EVENT_NAME_LEN_MAX + 1];
    struct 
    {
        u_int8_t digest[SHA_DIGEST_LENGTH];
        char filename[TCG_EVENT_NAME_LEN_MAX + 1];
    } ima_data;
    int filename_len;
};
int read_ima(struct Event *event, char *process_path_name);
void ima_reader_exit();
void print_ima(struct Event *event);
void store_ima(struct Event *event, char *filename);

#endif
