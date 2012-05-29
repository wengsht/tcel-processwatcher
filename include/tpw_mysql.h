#ifndef TPW_MYSQL_H
#define TPW_MYSQL_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mysql/mysql.h"

#define HOST     "localhost"
#define USER     "root"
#define PASS     "root"
#define DATABASE "TPW_verify"
#define TABLE    "hash_verify"
#define KEY      "filename_hash"
#define VALUE    "verify_str"

int init_db();
int put_verify_into_db(unsigned char* filename_hash,int filename_hash_len,unsigned char *verify_str,int verify_len);
int get_verify_from_db(unsigned char *verify_str,int*  verify_len,unsigned char* filename_hash,int filename_hash_len);
int check_verify_in_db(unsigned char *filename_hash,int filename_hash_len);
int close_db();

#endif
