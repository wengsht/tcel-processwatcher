/*   
 * 操作文件 /sys/kernel/security/ima/binary_runtime_measurements
 * 根据文件特征，用字符串hash 缓存到内存中
 *
 * hash 改用 glib 中的 GHashTable
 * 
 * 进程过多(PROCESS_MAX_NUM)时仅返回错误
 *
 *   */
#include <ima_reader_api.h>

static FILE *fp = NULL;
static struct GHashTable * g_hash_table = NULL;

static int output_begin = 0;

#ifdef IMA_RECOMPILED
#define ima_path "/sys/kernel/security/ima/binary_runtime_measurements"
#else
#define ima_path "./binary_runtime_measurements"
#endif

static int get_new_data();
static void renew_mm();
static int insert(struct Event *event);
static void my_hash_free_key(gpointer data);
static void my_hash_free_value(gpointer data);

int read_ima(struct Event *event, char *process_path_name)
{
    /*  试探文件是否被更新，是的话更新缓存 */
    renew_mm();

    /* 从ghash表中读出数据 */
    //struct Event *tmp = (struct Event *)g_hash_table_lookup(g_hash_table, process_path_name);
    struct Event *tmp = (struct Event *)g_hash_table_lookup(g_hash_table, process_path_name);

    if(NULL == tmp)
    {
        printf("PROCESS:%s not FOUND\n", process_path_name);
        return -1;
    }
    /*  直接从缓存中拷贝 */
    memcpy(event, tmp, sizeof(struct Event));

    return 0;
}

static void display_sha1_digest(u_int8_t *digest)
{
    int i;

    for (i = 0; i < 20; i++)
        printf(" %02X", (*(digest + i) & 0xff));
}
static void fdisplay_sha1_digest(FILE *file, u_int8_t *digest)
{
    int i;

    for (i = 0; i < 20; i++)
        fprintf(file, " %02X", (*(digest + i) & 0xff));
}
void print_ima(struct Event *event)
{
    printf("寄存器名：PCR%03u \n", event->header.pcr);

    printf ( "{文件度量结果+文件名}的度量结果:\n" );
    display_sha1_digest(event->header.digest);
    if (event->header.name_len > TCG_EVENT_NAME_LEN_MAX) {
        printf("%d ERROR: event name too long!\n",
                event->header.name_len);
        exit(1);
    }

    printf ( "\nIMA模板的名字:\n" ); //目前IMA项目组只实现了ima模板
    printf(" %s ", event->name);

    printf ( "\n文件的度量结果:\n" );
    display_sha1_digest(event->ima_data.digest);

    printf ( "\n被度量文件的名字:\n" );
    printf(" %s\n\n", event->ima_data.filename);
}
void store_ima(struct Event *event, char *filename)
{
    FILE *file;
    if(output_begin)
        file = fopen(filename, "a");
    else
    {
        file = fopen(filename, "w");
        output_begin = 1;
    }
    fprintf(file, "寄存器名：PCR%03u \n", event->header.pcr);

    fprintf (file,  "{文件度量结果+文件名}的度量结果:\n" );
    fdisplay_sha1_digest(file, event->header.digest);
    if (event->header.name_len > TCG_EVENT_NAME_LEN_MAX) {
        fprintf(file, "%d ERROR: event name too long!\n",
                event->header.name_len);
        exit(1);
    }

    fprintf ( file, "\nIMA模板的名字:\n" ); //目前IMA项目组只实现了ima模板
    fprintf(file, " %s ", event->name);

    fprintf ( file, "\n文件的度量结果:\n" );
    fdisplay_sha1_digest(file, event->ima_data.digest);

    fprintf ( file, "\n被度量文件的名字:\n" );
    fprintf(file, " %s\n\n", event->ima_data.filename);

    fclose(file);
}
/*  清理内存 */
void ima_reader_exit()
{
    g_hash_table_destroy(g_hash_table);

    fclose(fp);
}
/*  从文件中读取并存入缓存 */
static int get_new_data()
{
    int have_new_data = 0;
    struct Event event;

    have_new_data = fread(&event.header, sizeof(event.header), 1, fp);

    if(!have_new_data) return 0;

    /* 读取{文件度量结果+文件名}的度量结果 */
    memset(event.name, 0, sizeof(event.name));
    fread(event.name, event.header.name_len, 1, fp);

    memset(&event.ima_data, 0, sizeof event.ima_data);
    /*  读取IMA模板的名字  */
    fread(&event.ima_data.digest, sizeof event.ima_data.digest, 1, fp);
    /*  读取文件的度量结果  */
    fread(&event.filename_len, sizeof event.filename_len, 1, fp);
    /* 读取被度量文件的名字(绝对路径） */
    fread(event.ima_data.filename, event.filename_len, 1, fp);

    /* 新数据插入ghash表 */
    have_new_data = insert(&event);

    return have_new_data;
}
/*  新数据插入hash表 */
static int insert(struct Event *event)
{
    /* 新建 hash 表 */
    if(NULL == g_hash_table)
        g_hash_table = g_hash_table_new_full(g_str_hash, g_str_equal, my_hash_free_key, my_hash_free_value);

    struct Event *tmp = (struct Event *)malloc(sizeof(struct Event));
    memcpy(tmp, event, sizeof(struct Event));

    g_hash_table_insert(g_hash_table, strdup(event->ima_data.filename), tmp);

    return 1;
}
/*  循环更新缓存条目，知道文件无新内容 */
static void renew_mm()
{
    int have_new_data;
    if(NULL == fp)
    {
        fp = fopen(ima_path, "r");

        if(NULL == fp)
        {
            printf("\n### FAIL ###\n");
            printf("make sure your ima is opening !! and the ima data is in:\n"
                    "%s\nYou must be root to run this process\n\n", ima_path);
            exit(1);
        }
    }

    while(1)
    {
        have_new_data = get_new_data();

        if(!have_new_data) break;
    }
}
static void my_hash_free_key(gpointer data)
{
    free(data);
}
static void my_hash_free_value(gpointer data)
{
    free(data);
}
