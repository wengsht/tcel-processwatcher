#define _ATFILE_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#include "fanotify_func.h"
#include "fanotify-syscalllib.h"
#include "ima_reader_api.h"
#include "cryptoman.h"
#include "tpw_mysql.h"

#define PROCESS_BUF_LEN  1024
#define FILE_NAME_LEN_MX 1024
#define NORMAL_STR_LEN   100
#define SHA1_LEN         20

/*  fanotify初始化用到的一些flags */
#define INIT_FLAGS       FAN_CLASS_CONTENT 
#define INIT_EVENT_FLAGS O_RDONLY | O_LARGEFILE

//#define ALL_EVENT
/*  这个宏控制勾出哪些时间，包括open，close，access三种
 *  根据需要， demo默认只勾出access就足够了*/
#ifdef  ALL_EVENT
#define DEAFAULT_FAN_MASK FAN_OPEN | FAN_CLOSE | FAN_ACCESS | FAN_MODIFY | FAN_ACCESS_PERM
#else
#define DEAFAULT_FAN_MASK FAN_ACCESS | FAN_ACCESS_PERM
#endif

/*  TPM uid+authkey */
#define UID_LEN_MAX   20
#define PASS_LEN_MAX  1024
#define DEAFAULT_PASS "123456"
#define DEAFAULT_UID  "1000"

/*  用户交互命令对应的处理id(switch) */
#define EXIT_CMD     0
#define WATCH_CMD    1
#define UNWATCH_CMD  2
#define LOGIN_CMD    3
#define HELP_CMD     4

/* 全局变量running的两个状态,便于结束程序 */
#define PROCESS_RUNNING 1
#define PROCESS_EXIT    0

/*  CryptoMan uid && pass */
char uid[UID_LEN_MAX]   = DEAFAULT_UID;
char auth[PASS_LEN_MAX] = DEAFAULT_PASS;
struct Cryptoman_Context context;

#define SHA1_LEN 20
#define BLOCK_LEN 4096

/*  交互线程，放在全局便于kill */
pthread_t demo_thread_id;

/*  for fanotify */
/*  set premptive ignores (go faster) */
/*  如果opt_fast打开，会跳过相同文件的deny判断过程， */
/*   */
bool opt_fast = false, opt_ignore_perm = true;
fd_set          rfds;

/*  control run or exit */
int running;
/*  利用这个标志阻塞用户交互线程，因为认证失败时需要用户输入Y/N */
int getting_cmd;

static void sigterm(int sig);

static int is_dir(char *dir_name);
static int is_exe(mode_t mode);
static void check_dir_last(char *dir_name);
void set_pre_dir(char *dir_name);
static void help_output();

static void change_dir_flags(int fan_fd, char *dir_name, int mark_flags);
static void watch_dir_enable(int fan_fd, char *dir_name);
static void watch_dir_unable(int fan_fd, char *dir_name);

/*  用户交互 */
static int  get_cmd_id(char *cmd);
static void cmd_action(int fan_fd, int cmd_id);

/*  根据mask得到相应类型的字符串表示(用于事件表示，如open/close/access) */
static void get_acc_type(char *output, int mx_len, int mask);

/*  fanotify 拒绝操作判断,真正与CryptoMan和Mysql交互的地方 */
static int handle_perm(int fan_fd, struct fanotify_event_metadata *metadata, char *path);

/*  监听线程 */
static void process_watch_start(int fan_fd);
/*  用户交互线程，支持添加目录监控 */
static void *demo_start(void *arg);

int main(int argc, char *argv[])
{
    running = PROCESS_RUNNING;
    getting_cmd = 1;

    signal(SIGHUP, sigterm);
    signal(SIGINT, sigterm);
    signal(SIGTERM, sigterm);

    int  rc;
    void *thread_result;
    int  fan_fd;

    /*  init mysql && CryptoMan && fanotify*/
    rc = Cryptoman_CreateContext(&context, ProcessWatcher,atoi(uid), strlen(auth), auth);
    if(0 != rc)
        goto fail;

    fan_fd = fanotify_init(INIT_FLAGS, INIT_EVENT_FLAGS);
	if (fan_fd < 0)
		goto fail;

	FD_ZERO(&rfds);
	FD_SET(fan_fd, &rfds);

    rc = init_db();
    if(0 != rc)
        goto fail;
    /*  init done */

    /* 用户交互线程(添加watch目录，unwatch什么的)  */
    rc = pthread_create(&demo_thread_id, NULL, demo_start, (void *)&fan_fd);
    if(0 != rc)
        goto fail;

    /*  完整性度量线程 */
    process_watch_start(fan_fd);

	return 0;
fail:
	fprintf(stderr, "%s\n", strerror(errno));
	return 1;
}

/*  
 *  根据勾出来得metadata->fd从ima取得hash值
 *  利用CryptoMan做认证
 *  策略与ProceesWatch几乎一样
 *
 *  */
static int handle_perm(int fan_fd, struct fanotify_event_metadata *metadata, char *path)
{
	struct fanotify_response response_struct;
    struct Event ima_buffer;
    struct stat _stat;
	int ret;
    char ok[NORMAL_STR_LEN];

    unsigned char verify_str[BLOCK_LEN];
    unsigned char filename_hash[SHA1_LEN];
    int verify_len = BLOCK_LEN;
    int hashLen = SHA1_LEN;

	response_struct.fd = metadata->fd;

    fstat(metadata->fd, &_stat);
    if(!is_exe(_stat.st_mode))
        goto no_deny;

    if(0 != read_ima(&ima_buffer, path))
    {
        printf("ima is not working well!!\n");

        goto no_deny;
    }

    Cryptoman_MakeHash(&context, strlen(ima_buffer.ima_data.filename), (unsigned char *)ima_buffer.ima_data.filename, &hashLen, filename_hash);

    //SHA1(ima_buffer.ima_data.filename, strlen(ima_buffer.ima_data.filename), filename_hash);

    /*  如果在数据库中找到，需要做度量 */
    if(check_verify_in_db(filename_hash, hashLen))
    {
        get_verify_from_db(verify_str, &verify_len, filename_hash, hashLen);
        if(0 == Cryptoman_VerifySign(&context, SHA1_LEN, ima_buffer.ima_data.digest, verify_len, verify_str))
        {
            printf("### [TPM]: process measured success!!! ###\n");
            goto no_deny;
        }
        else
        {
            getting_cmd = 0;
            printf("### [TPM]: the process is changed!! ###\n");
            
            printf("DO YOU WANT TO RUN IT?[Y/N]:");
            scanf("%s", ok);

            getting_cmd = 1;
            if(strncmp("Y", ok, 1) == 0)
                goto renew;
            else
                goto deny;
        }
    }
    else
    {
renew:
        if(0 != Cryptoman_MakeSign(&context, SHA1_LEN, ima_buffer.ima_data.digest, &verify_len, verify_str))
        {
            printf("TPM Error\n");
        }
        else
            put_verify_into_db(filename_hash, SHA1_LEN, verify_str, verify_len);

        goto no_deny;
    }
deny:
    response_struct.response = FAN_DENY;
    ret = write(fan_fd, &response_struct, sizeof(response_struct));
    goto out;
no_deny: 
    response_struct.response = FAN_ALLOW;
    ret = write(fan_fd, &response_struct, sizeof(response_struct));
out:
    if (ret < 0)
        return ret;
    return 0;
}

static void process_watch_start(int fan_fd)
{
    int  len;
    char buf[PROCESS_BUF_LEN], acc_type[100];
    char path[PATH_MAX];
    int  path_len;

    /*  利用select 阻塞，fanotify的fan_fd,在每个监控结束后是递增，这样很容易控制 */
    while (select(fan_fd+1, &rfds, NULL, NULL, NULL) < 0)
        if (errno != EINTR)
            goto fail;

    /*  循环监控 */
    while(PROCESS_RUNNING == running && (len = read(fan_fd, buf, sizeof(buf))) > 0) 
    {
        struct fanotify_event_metadata *metadata;

        metadata = (void *)buf;

        while(FAN_EVENT_OK(metadata, len)) 
        {
            if (metadata->vers < 2) {
                fprintf(stderr, "Kernel fanotify version too old\n");
                goto fail;
            }

            /*  设了了opt_fast的话将忽略很多相同文件的钩子,demo默认关闭 */
            if (metadata->fd >= 0 &&
                    opt_fast &&
                    set_ignored_mask(fan_fd, metadata->fd,
                        FAN_ALL_EVENTS | FAN_ALL_PERM_EVENTS))
                goto fail;

            /*  这部分通过软链接取得完整路径名 */
            if (metadata->fd >= 0) 
            {
                sprintf(path, "/proc/self/fd/%d", metadata->fd);
                path_len = readlink(path, path, sizeof(path)-1);
                if (path_len < 0)
                    goto fail;
                path[path_len] = '\0';
                printf("path: [%s]", path);
            } 
            else
                printf("Error from File System!!!:");

            set_special_ignored(fan_fd, metadata->fd, path);

            printf(" pid=[%ld]", (long)metadata->pid);

            /*  根据mask取得描述mask得字符串存于acc_type中 */
            get_acc_type(acc_type, NORMAL_STR_LEN, metadata->mask);

            printf(" acc_type: {%s}\n", acc_type);
            printf("[uid:%s]@tpw->", uid);

            /*  PERM标识就是表示需要响应是否deny的 */
            if(metadata->mask & FAN_ALL_PERM_EVENTS)
            {
                /*  此函数做认证并决定deny与否 */
                if(handle_perm(fan_fd, metadata, path))
                    goto fail;

                if (metadata->fd >= 0 &&
                        opt_ignore_perm &&
                        set_ignored_mask(fan_fd, metadata->fd,
                            metadata->mask))
                    goto fail;
            }

            fflush(stdout);

            metadata = FAN_EVENT_NEXT(metadata, len);
        }
        /*  阻塞 */
        while (select(fan_fd+1, &rfds, NULL, NULL, NULL) < 0)
            if (errno != EINTR)
            goto fail;
    }

fail:
    printf("error\n");
}

/*  功能函数，无需看 */
static void get_acc_type(char *output, int mx_len, int mask)
{
    memset(output, 0, mx_len);
    if (mask & FAN_ACCESS)
        strcat(output, "[access]");
    if (mask & FAN_OPEN)
        strcat(output, "[open]");
    if (mask & FAN_MODIFY)
        strcat(output, "[modify]");
    if (mask & FAN_CLOSE) {
        if (mask & FAN_CLOSE_WRITE)
            strcat(output, "[close(writable)]");
        if (mask & FAN_CLOSE_NOWRITE)
            strcat(output, "[close]");
    }
    if (mask & FAN_OPEN_PERM)
        strcat(output, "[open_perm]");
    if (mask & FAN_ACCESS_PERM)
        strcat(output, "[access_perm]");
}
static int get_cmd_id(char *cmd)
{
    if(0 == strcmp(cmd, "watch"))
        return WATCH_CMD;
    if(0 == strcmp(cmd, "unwatch"))
        return UNWATCH_CMD;
    if(0 == strcmp(cmd, "exit"))
        return EXIT_CMD;
    if(0 == strcmp(cmd, "login"))
        return LOGIN_CMD;

    return HELP_CMD;
}

static void cmd_action(int fan_fd, int cmd_id)
{
    char path[FILE_NAME_LEN_MX];
    switch(cmd_id)
    {
    case WATCH_CMD:
        scanf("%s", path);
        if(is_dir(path))
            watch_dir_enable(fan_fd, path);
        else
            mark_object(fan_fd, path, AT_FDCWD, DEAFAULT_FAN_MASK, FAN_MARK_ADD);
        break;
    case UNWATCH_CMD:
        scanf("%s", path);
        if(is_dir(path))
            watch_dir_unable(fan_fd, path);
        else
            mark_object(fan_fd, path, AT_FDCWD, DEAFAULT_FAN_MASK, FAN_MARK_REMOVE);
            
        break;
    case HELP_CMD:
        help_output();
        break;

    case EXIT_CMD:
        sigterm(SIGINT);
    }
}

/*  输出帮助信息 */
static void help_output()
{
    printf("\n----------------------------------------------------\n");
    printf(  "|####################USAGE HELP####################|\n"
             "| 1. watch dir/file                                |\n"
             "|    用于添加监控目录，如果输入的是目录            |\n"
             "|    则监控整个目录树，也可监控单一文件            |\n"
             "|                                                  |\n"
             "| 2. unwatch dir/file                              |\n"
             "|    取消监控，用法和[1]一样                       |\n"
             "|                                                  |\n"
             "| 3. exit                                          |\n"
             "|    结束监控程序(<Ctrl-c>)                        |\n"
             "|                                                  |\n"
             "| 4. help                                          |\n"
             "|                                                  |\n"
             "|######################注意########################|\n"
             "| 1. 程序包含两个线程：用户交互和监控线程          |\n"
             "|    由于监控线程在发现度量失败时要用户输入        |\n"
             "|    故会有一些控制策略，交互不是很友好            |\n"
             "|                                                  |\n"
             "|    如果已经输入[Y/N]而到这里，请再输入一次       |\n"
             "|    见谅!!                                        |\n"
             "----------------------------------------------------\n\n");
}

/*  程序结束时调用，清空CryptoMan结构体,Mysql结束操作等 */
static void sigterm(int sig)
{
    if(running && (SIGHUP == sig || SIGINT == sig || SIGTERM == sig))
    {
        running = PROCESS_EXIT;

        Cryptoman_CloseContext(&context);

        close_db();

        printf("###Process Watch End && Good Bye###\n");

        pthread_cancel(demo_thread_id);

        exit(0);
    }
}
static int is_dir(char *dir_name)
{
    DIR *pdir;
    if(NULL == (pdir = opendir(dir_name)))
    {
        int save_errno = errno;
        closedir(pdir);

        if( save_errno == ENOENT )
            return -1;
        else
            return 0;
    }
    else
    {
        closedir(pdir);
        return 1;
    }
}
static int is_exe(mode_t mode)
{
	if ( (mode & S_IXOTH) || (mode & S_IXGRP) || (mode & S_IXUSR) ) {
		if ( S_ISDIR(mode) )
			return 0;
		else 
			return 1;
	} else
		return 0;
}

/*  格式化目录，目录名后面都拼上'/'
 *  如"/home/test" -> "/home/test/  */
static void check_dir_last(char *dir_name)
{
    if(dir_name[strlen(dir_name)-1] != '/')
        strcat(dir_name, "/");
}

/* 回到上层目录
 * 如"/home/test/" -> "/home/"
 */
void set_pre_dir(char *dir_name)
{
    int len = strlen(dir_name);

    int i = len-1;
    if('/' == dir_name[i]) i--;
    for(; i >= 0 && dir_name[i] != '/'; i--) 
        dir_name[i] = '\0';
    if(i < 0) dir_name[0] = '/';
}

/*  对目录做递归操作，支持监控和取消监控 */
static void change_dir_flags(int fan_fd, char *dir_name, int mark_flags)
{
    mark_object(fan_fd, dir_name, AT_FDCWD, DEAFAULT_FAN_MASK | FAN_EVENT_ON_CHILD, mark_flags);

    DIR *pdir;
    struct dirent *entry;
    struct stat statbuf;

    if(NULL == (pdir = opendir(dir_name)))
    {
        goto fail;
    }
    while(NULL != (entry = readdir(pdir)))
    {
        lstat(entry->d_name, &statbuf);

        if(S_ISDIR(statbuf.st_mode))
        {
            if(!strcmp(".", entry->d_name) || !strcmp("..", entry->d_name))
                continue;

            strcat(dir_name, entry->d_name);
            check_dir_last(dir_name);

            chdir(entry->d_name);
            change_dir_flags(fan_fd, dir_name, mark_flags);

            set_pre_dir(dir_name);
        }
    }
    chdir("..");
    closedir(pdir);

    return ;
    
fail:
    printf("change_dir_stags:  error!!\n");
}

/*  递归watch目录 */
static void watch_dir_enable(int fan_fd, char *dir_name)
{
    check_dir_last(dir_name);
    chdir(dir_name);

    change_dir_flags(fan_fd, dir_name, FAN_MARK_ADD);
}

/*  递归unwatch目录 */
static void watch_dir_unable(int fan_fd, char *dir_name)
{
    check_dir_last(dir_name);
    chdir(dir_name);

    change_dir_flags(fan_fd, dir_name, FAN_MARK_REMOVE);
}
/*  交互线程 */
static void *demo_start(void *arg)
{
    int fan_fd = *(int *)arg;
    char cmd[NORMAL_STR_LEN];
    int cmd_id;

    printf("###process watch start!!###\n");
    while(running)
    {
        while(0 == getting_cmd) sleep(1);

        printf("[uid:%s]@tpw->", uid);
        scanf("%s", cmd);

        cmd_id = get_cmd_id(cmd);

        cmd_action(fan_fd, cmd_id);
    }
}
