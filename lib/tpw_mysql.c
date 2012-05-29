#include "tpw_mysql.h"

MYSQL* mysql;
MYSQL_RES* results;
MYSQL_ROW record;

int init_db()
{
   if(mysql_library_init(0,NULL,NULL))
   {
       fprintf(stderr,"Can't initialize the mysql library!\n");
       return -1;
   }
   mysql = mysql_init(NULL);
   if(mysql == NULL)
   {
       fprintf(stderr,"Can't initialize the mysql struct!\n");
       return -1;
   }


   //connect
   if(NULL == mysql_real_connect(mysql,HOST,USER,PASS,DATABASE,0,NULL,0))
   {
       fprintf(stderr,"Can't connect to the database TPW_verify\n");
       return -1;
   }

   return 0;
}




int put_verify_into_db(unsigned char* filename_hash,int filename_hash_len,unsigned char *verify_str,int verify_len)
{
    //convert to hex stirng
    
    unsigned char buf[40];
    unsigned char query[8500];

    int index,i;

    sprintf((char*)query,"delete from %s where %s = 0x",TABLE,KEY);
    index = strlen(query);

    for(i = 0;i < filename_hash_len;i++)
    {
        sprintf((char*)(query+index),"%02x",filename_hash[i]);
        index += 2;
    }

    int rc = mysql_real_query(mysql,query,index);

    sprintf((char*)query,"insert into %s values(0x",TABLE);
    index = strlen(query);

    for(i = 0;i < filename_hash_len; i++)
    {
        sprintf((char*)(query+index),"%02x",filename_hash[i]);
        index += 2;
    }
    query[index++] = ',';
    query[index++] = '0';
    query[index++] = 'x';

    for(i = 0;i < verify_len;i++)
    {
        sprintf((char*)(query+index),"%02x",verify_str[i]);
        index += 2;
    }
    query[index++] = ')';

    rc = mysql_real_query(mysql,query,index);
    if(rc != 0)
    {
        printf("insert fail!\n");
        return -1;
    }

    return 0;
    
}



int get_verify_from_db(unsigned char *verify_str,int*  verify_len,unsigned char* filename_hash,int filename_hash_len)
{
    int index,i;
    unsigned char query[8500];

    sprintf((char*)query,"select %s from %s where %s = 0x",VALUE,TABLE,KEY);
    index = strlen(query);

    for(i = 0;i < filename_hash_len;i++)
    {
        sprintf((char*)(query+index),"%02x",filename_hash[i]);
        index += 2;
    }

    int rc = mysql_real_query(mysql,query,index);

    if(rc)
    {
        printf("can't complete query\n");
        return -1;
    }
    if((results = mysql_use_result(mysql)) == NULL)
    {
        printf("can't get the result\n");
        return -1;
    }

    if((record = mysql_fetch_row(results)) != NULL)
    {
        unsigned long * len = mysql_fetch_lengths(results);
        if(len[0] == 0)
        {
           *verify_len = 0;
        }else
        {
           // printf("%d ",len[0]);
            for(i = 0;i < len[0]; i++)
            {
               // printf("%02x ",record[0][i]);
                verify_str[i] = record[0][i];
            }
           *verify_len = len[0];
        }

        mysql_free_result(results);
        return 0;

    }else{
        if(mysql_errno(mysql) == 0)
        {
            //no such key
            *verify_len = 0;
            mysql_free_result(results);
            return 0;
        }else
        {
            printf("error occurrs when fetching\n");
            mysql_free_result(results);
            return -1;
        }
    }

    mysql_free_result(results);
    return 0;
}

int close_db()
{
   // mysql_free_result(results);
    mysql_close(mysql);
    mysql_library_end();
}


int check_verify_in_db(unsigned char *filename_hash,int filename_hash_len)
{
    int index,i;
    unsigned char query[200];

    sprintf((char*)query,"select %s from %s where %s = 0x",VALUE,TABLE,KEY);
    index = strlen(query);

    for(i = 0;i < filename_hash_len;i++)
    {
        sprintf((char*)(query+index),"%02x",filename_hash[i]);
        index += 2;
    }

    int rc = mysql_real_query(mysql,query,index);

    if(rc)
    {
        printf("can't complete query\n");
        return -1;
    }
    if((results = mysql_store_result(mysql)) == NULL)
    {
        printf("can't get the result\n");
        return -1;
    }

    if(mysql_num_rows(results) == 0)
    {
        //no such record
        mysql_free_result(results);
        return 0;
    }else 
    {  
        mysql_free_result(results);
        return 1;
    }
}
