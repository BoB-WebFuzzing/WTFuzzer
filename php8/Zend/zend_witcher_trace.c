#include "../Zend/zend_compile.h"
#include "zend.h"
#include "zend_modules.h"
#include <unistd.h>
#include <string.h> /* For the real memset prototype.  */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <sys/wait.h>

int value_diff_changes(char *var1, char *var2);
void value_diff_report(char *var1, char *var2, int bitmapLoc);
void var_diff_report(char *var1, int bitmapLoc, int var_type);
void dbg_printf(const char *fmt, ...);

#ifdef WITCHER_DEBUG
#define debug_print(xval) \
    do                    \
    {                     \
        dbg_printf xval;  \
    } while (0)
#else
#define debug_print(fmt, ...)
#endif

/***** END new for HTTP direct ********/

#define MAPSIZE 65536
#define TRACE_SIZE 128 * (1024 * 1024) // X * megabytes

#define SHM_ENV_VAR "__AFL_SHM_ID"

#define STDIN_FILENO 0

static int last = 0;
static int op = 0;

static int MAX_CMDLINE_LEN = 128 * 1024;

static unsigned char *afl_area_ptr = NULL;

unsigned int afl_forksrv_pid = 0;
static unsigned char afl_fork_child;

#define FORKSRV_FD 198
#define TSL_FD (FORKSRV_FD - 1)

#define MAX_VARIABLES 1024
char *variables[3][MAX_VARIABLES];
unsigned char variables_used[3][MAX_VARIABLES];
int variables_ptr[3] = {0, 0, 0};

char *traceout_fn, *traceout_path;

int nextVar2_is_a_var = -1;
bool wc_extra_instr = true;

static bool start_tracing = false;

static char *env_vars[2] = {"HTTP_COOKIE", "QUERY_STRING"};
char *login_cookie = NULL, *mandatory_cookie = NULL, *preset_cookie = NULL;
char *witcher_print_op = NULL;

char *main_filename;
char session_id[40];
int saved_session_size = 0;

int trace[TRACE_SIZE];
int trace_index = 0;

int pipefds[2];

int top_pid = 0;

void dbg_printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

/**
 * Mostly taken from the afl_forkserver code provided with AFL
 * Injects a fork server into php_cgi to speed things up
 */
static void afl_forkserver()
{
    printf("afl_forkserver()\n");

    static unsigned char tmp[4];

    if (!afl_area_ptr)
        return;
    if (write(FORKSRV_FD + 1, tmp, 4) != 4)
        return;

    afl_forksrv_pid = getpid();

    /* All right, let's await orders... */
    int claunch_cnt = 0;
    while (1)
    {

        pid_t child_pid = -1;
        int status, t_fd[2];

        /* Whoops, parent dead? */
        if (read(FORKSRV_FD, tmp, 4) != 4)
            exit(2);

        /* Establish a channel with child to grab translation commands. We'll
           read from t_fd[0], child will write to TSL_FD. */
        if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0)
            exit(3);
        close(t_fd[1]);
        claunch_cnt++;
        child_pid = fork();

        fflush(stdout);
        if (child_pid < 0)
            exit(4);

        if (!child_pid)
        { // child_pid == 0, i.e., in child

            FILE *fptr;
            fptr = fopen("/tmp/httpreqr.pid", "w");
            if (fptr)
            {
                fprintf(fptr, "%d", getpid());
                fclose(fptr);
            }

            /* Child process. Close descriptors and run free. */
            debug_print(("\t\t\tlaunch cnt = %d Child pid == %d, but current pid = %d\n", claunch_cnt, child_pid, getpid()));
            fflush(stdout);
            afl_fork_child = 1;
            close(FORKSRV_FD);
            close(FORKSRV_FD + 1);
            close(t_fd[0]);
            return;
        }

        /* Parent. */

        close(TSL_FD);

        if (write(FORKSRV_FD + 1, &child_pid, 4) != 4)
        {
            debug_print(("\t\tExiting Parent %d with 5\n", child_pid));
            exit(5);
        }

        /* Get and relay exit status to parent. */
        int waitedpid = waitpid(child_pid, &status, 0);
        if (waitedpid < 0)
        {
            printf("\t\tExiting Parent %d with 6\n", child_pid);
            exit(6);
        }

        if (write(FORKSRV_FD + 1, &status, 4) != 4)
        {
            exit(7);
        }
    }
}

void load_variables(char *str, int var_type)
{
    printf("load_variables()\n");
    char *tostr = strdup(str);
    char *end_str;
    char *token = strtok_r(tostr, "&", &end_str);

    while (token != NULL)
    {
        char *end_token;
        char *dup_token = strdup(token);
        char *subtok = strtok_r(dup_token, "=", &end_token);

        if (subtok != NULL && variables_ptr[var_type] < MAX_VARIABLES)
        {
            char *first_part = strdup(subtok);
            subtok = strtok_r(NULL, "=", &end_token);
            int len = strlen(first_part);
            if (len > 2)
            {
                bool unique = true;
                for (int i = 0; i < variables_ptr[var_type]; i++)
                {
                    if (strcmp(first_part, variables[var_type][i]) == 0)
                    {
                        unique = false;
                        break;
                    }
                }
                if (unique)
                {
                    int cur_ptr = variables_ptr[var_type];
                    variables[var_type][cur_ptr] = (char *)malloc(len + 1);
                    strncpy(variables[var_type][cur_ptr], first_part, len);
                    variables[var_type][cur_ptr][len] = '\x00';
                    variables_used[var_type][cur_ptr] = 0;
                    variables_ptr[var_type]++;
                }
            }
            token = strtok_r(NULL, "&", &end_str);
        }
        else
        {
            break;
        }
    }
}

char *replace_char(char *str, char find, char replace)
{
    printf("replace_char()\n");
    char *current_pos = strchr(str, find);
    while (current_pos)
    {
        *current_pos = replace;
        current_pos = strchr(current_pos, find);
    }
    return str;
}

char *format_to_json(char *str)
{
    printf("format_to_json()\n");

    char *tostr = strdup(str);
    char *outstr;
    outstr = (char *)malloc(strlen(str) + 1024);
    char *end_str;
    char *token = strtok_r(tostr, "&", &end_str);
    outstr = strcat(outstr, "{");

    while (token != NULL)
    {
        char jsonEleOut[strlen(str) + 7];
        char *end_token;
        char *dup_token = strdup(token);
        char *first_part = strtok_r(dup_token, "=", &end_token);
        char *sec_part = strtok_r(NULL, "=", &end_token);
        if (sec_part)
        {
            sprintf(jsonEleOut, "\"%s\":\"%s\",", first_part, sec_part);
        }
        else
        {
            sprintf(jsonEleOut, "\"%s\":\"\",", first_part);
        }
        outstr = strcat(outstr, jsonEleOut);
        token = strtok_r(NULL, "&", &end_str);
    }

    outstr[strlen(outstr) - 1] = '}';
    outstr[strlen(outstr)] = '\x00';

    return outstr;
}

/**
 * sets up the cgi environment for a cgi request
 */
void prefork_cgi_setup()
{
    printf("prefork_cgi_setup()\n");
    debug_print(("[\e[32mWitcher\e[0m] Starting SETUP_CGI_ENV  \n"));
    char *tmp = getenv("DOCUMENT_ROOT");
    if (!tmp)
    {
        setenv("DOCUMENT_ROOT", "/app", 1); // might be important if your cgi read/writes there
    }
    setenv("HTTP_REDIRECT_STATUS", "1", 1);

    setenv("HTTP_ACCEPT", "*/*", 1);
    setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);

    setenv("PATH", "/usr/bin:/tmp:/app", 1); // HTTP URL PATH
    tmp = getenv("REQUEST_METHOD");
    if (!tmp)
    {
        setenv("REQUEST_METHOD", "POST", 1); // Usually GET or POST
    }
    setenv("REMOTE_ADDR", "127.0.0.1", 1);

    setenv("CONTENT_TYPE", "application/x-www-form-urlencoded", 1);
    setenv("REQUEST_URI", "SCRIPT", 1);
    login_cookie = getenv("LOGIN_COOKIE");

    // Save cookie value in /tmp/cookie.txt
    FILE *file = fopen("/tmp/cookie.txt", "w");

    if (file == NULL)
    {
        fprintf(stderr, "Failed to open the file.\n");
    }
    else
    {
        fprintf(file, "%s\n", login_cookie);

        fclose(file);
    }

    char *preset_cookie = (char *)malloc(MAX_CMDLINE_LEN);
    memset(preset_cookie, 0, MAX_CMDLINE_LEN);

    if (login_cookie)
    {
        strcat(preset_cookie, login_cookie);
        setenv(env_vars[0], login_cookie, 1);

        if (!strchr(login_cookie, ';'))
        {
            strcat(login_cookie, ";");
        }
        debug_print(("[\e[32mWitcher\e[0m] LOGIN COOKIE %s\n", login_cookie));
        char *name = strtok(login_cookie, ";=");
        while (name != NULL)
        {
            char *value = strtok(NULL, ";=");
            if (value != NULL)
            {
                debug_print(("\t%s==>%s\n", name, value)); // printing each token
            }
            else
            {
                debug_print(("\t%s==> NADA \n", name)); // printing each token
            }

            if (value != NULL)
            {
                int thelen = strlen(value);
                if (thelen >= 24 && thelen <= 32)
                {
                    debug_print(("[\e[32mWitcher\e[0m] session_id = %s, len=%d\n", value, thelen));
                    strcpy(session_id, value);
                    char filename[64];
                    char sess_fn[64];
                    sprintf(sess_fn, "../../../../../../../tmp/sess_%s", value);
                    setenv("SESSION_FILENAME", sess_fn, 1);

                    sprintf(filename, "../../../../../../../tmp/save_%s", value);

                    // saved_session_size = fsize(filename);

                    debug_print(("\t[WC] SESSION ID = %s, saved session size = %d\n", filename, saved_session_size));
                    break;
                }
            }
            name = strtok(NULL, ";=");
        }
        debug_print(("[\e[32mWitcher\e[0m] LOGIN ::> %s\n", login_cookie));
    }
    mandatory_cookie = getenv("MANDATORY_COOKIE");
    if (mandatory_cookie && strlen(mandatory_cookie) > 0)
    {
        strcat(preset_cookie, "; ");
        strcat(preset_cookie, mandatory_cookie);
        debug_print(("[\e[32mWitcher\e[0m] MANDATORY COOKIE = %s\n", preset_cookie));
    }
    witcher_print_op = getenv("WITCHER_PRINT_OP");
}
void setup_cgi_env()
{

    printf("setup_cgi_env()\n");

    // strict is set for the modified /bin/dash
#ifdef WITCHER_DEBUG
    FILE *logfile = fopen("/tmp/wrapper.log", "a+");
    fprintf(logfile, "----Start----\n");
    // printf("starting\n");
#endif

    static int num_env_vars = sizeof(env_vars) / sizeof(char *);

    char in_buf[MAX_CMDLINE_LEN];
    memset(in_buf, 0, MAX_CMDLINE_LEN);
    size_t bytes_read = read(0, in_buf, MAX_CMDLINE_LEN - 2);

    int zerocnt = 0;
    for (int cnt = 0; cnt < MAX_CMDLINE_LEN; cnt++)
    {
        if (in_buf[cnt] == 0)
        {
            zerocnt++;
        }
        if (zerocnt == 3)
        {
            break;
        }
    }

    pipe(pipefds);

    dup2(pipefds[0], STDIN_FILENO);
    // close(STDIN_FILENO);

    int real_content_length = 0;
    char *saved_ptr = (char *)malloc(MAX_CMDLINE_LEN);
    char *ptr = in_buf;
    int rc = 0;
    char *cwd;
    int errnum;
    // struct passwd *p = getpwuid(getuid());  // Check for NULL!
    long size = pathconf(".", _PC_PATH_MAX);
    char *dirbuf = (char *)malloc((size_t)size);
    size_t bytes_used = 0;

    // loop through the strings read via stdin and break at each \x00
    // Cookies, Query String, Post (via re-writting to stdin)

    char *cookie = (char *)malloc(MAX_CMDLINE_LEN);
    memset(cookie, 0, MAX_CMDLINE_LEN);

    // Get cookie value from /tmp/cookie.txt
    FILE *file = fopen("/tmp/cookie.txt", "r");

    if (file == NULL)
    {
        fprintf(stderr, "Failed to open the file.\n");
    }

    if (fgets(cookie, MAX_CMDLINE_LEN, file) == NULL)
    {
        fprintf(stderr, "Failed to read from the file.\n");
        fclose(file); // 파일 닫기
    }

    char *newline = strchr(cookie, '\n');
    if (newline != NULL)
    {
        *newline = '\0';
    }

    fclose(file);

    setenv(env_vars[0], cookie, 1);
    char *post_data = (char *)malloc(MAX_CMDLINE_LEN);
    memset(post_data, 0, MAX_CMDLINE_LEN);
    char *query_string = (char *)malloc(MAX_CMDLINE_LEN);
    memset(query_string, 0, MAX_CMDLINE_LEN);

    setenv(env_vars[1], query_string, 1);

    while (!*ptr)
    {
        bytes_used++;
        ptr++;
        rc++;
    }
    while (*ptr || bytes_used < bytes_read)
    {
        memcpy(saved_ptr, ptr, strlen(ptr) + 1);
        if (rc < 3)
        {
            load_variables(saved_ptr, rc);
        }
        if (rc < num_env_vars)
        {

            if (rc == 0)
            {
                strcat(cookie, "; ");
                strcat(cookie, saved_ptr);
                cookie = replace_char(cookie, '&', ';');
                setenv(env_vars[rc], cookie, 1);
            }
            else if (rc == 1)
            {
                strcat(query_string, "&");
                strcat(query_string, saved_ptr);

                setenv(env_vars[rc], query_string, 1);
            }
            else
            {

                setenv(env_vars[rc], saved_ptr, 1);
            }

            if (afl_area_ptr != NULL)
            {
                afl_area_ptr[0xffdd] = 1;
            }
        }
        else if (rc == num_env_vars)
        {
            char *json = getenv("DO_JSON");
            if (json)
            {
                saved_ptr = format_to_json(saved_ptr);
                debug_print(("\e[32m\tDONE JSON=%s\e[0m\n", saved_ptr));
            }

            real_content_length = write(pipefds[1], saved_ptr, strlen(saved_ptr));
            write(pipefds[1], "\n", 1);

            // debug_print(("\tReading from %d and writing %d bytes to %d \n", real_content_length, pipefds[0], pipefds[1]));
            // debug_print(("\t%-15s = \033[33m%s\033[0m \n", "POST", saved_ptr));

            char snum[20];
            sprintf(snum, "%d", real_content_length);
            memcpy(post_data, saved_ptr, strlen(saved_ptr) + 1);
            setenv("E", saved_ptr, 1);
            setenv("CONTENT_LENGTH", snum, 1);
        }

        rc++;
        while (*ptr)
        {
            ptr++;
            bytes_used++;
        }
        ptr++;
        bytes_used++;
    }
    debug_print(("[\e[32mWitcher\e[0m] %lib read / %lib used \n", bytes_read, bytes_used));
    if (afl_area_ptr != NULL)
    {
        afl_area_ptr[0xffdd] = 1;
    }
    if (cookie)
    {
        debug_print(("\t%-14s = \e[33m %s\e[0m\n", "COOKIES", cookie));
    }
    if (query_string)
    {
        debug_print(("\t%-14s = \e[33m %s\e[0m\n", "QUERY_STRING", query_string));
    }
    if (post_data)
    {
        debug_print(("\t%-9s (%s) = \e[33m %s\e[0m\n", "POST_DATA", getenv("CONTENT_LENGTH"), post_data));
    }
    debug_print(("\n"));

    free(saved_ptr);
    free(cookie);
    free(query_string);
    free(post_data);

    close(pipefds[0]);
    close(pipefds[1]);
#ifdef WITCHER_DEBUG
    fclose(logfile);
#endif

    fflush(stderr);
}
/************************************************************************************************/
/********************************** HTTP direct **************************************************/
/************************************************************************************************/
void afl_error_handler(int nSignum)
{
    printf("afl_error_handler()\n");
    FILE *elog = fopen("/tmp/witcher.log", "a+");
    if (elog)
    {
        fprintf(elog, "\033[36m[Witcher] detected error in child but AFL_META_INFO_ID is not set. !!!\033[0m\n");
        fclose(elog);
    }
}

/************************************************************************************************/
/********************************** END HTTP direct **************************************************/
/************************************************************************************************/

unsigned char *cgi_get_shm_mem(char *ch_shm_id)
{
    printf("cgi_get_shm_mem()\n");
    char *id_str;
    int shm_id;

    if (afl_area_ptr == NULL)
    {
        id_str = getenv(SHM_ENV_VAR);
        if (id_str)
        {
            shm_id = atoi(id_str);
            afl_area_ptr = shmat(shm_id, NULL, 0);
        }
        else
        {

            afl_area_ptr = malloc(MAPSIZE);
        }
    }
    return afl_area_ptr;
}

/**
 * The witcher init, is needed at the start of the script and is only executed once per child
 * it sets up the tracing enviornment
 */
void witcher_cgi_trace_init(char *ch_shm_id)
{
    printf("witcher_cgi_trace_init()\n");
    debug_print(("[\e[32mWitcher\e[0m] in Witcher trace\n\t\e[34mSCRIPT_FILENAME=%s\n\t\e[34mAFL_PRELOAD=%s\n\t\e[34mLD_LIBRARY_PATH=%s\e[0m\n", getenv("SCRIPT_FILENAME"), getenv("AFL_PRELOAD"), getenv("LD_LIBRARY_PATH"), getenv("LOGIN_COOKIE")));

    if (getenv("WC_INSTRUMENTATION"))
    {
        start_tracing = true;
        debug_print(("[Witcher] \e[32m WC INSTUMENTATION ENABLED \e[0m "));
    }
    else
    {
        debug_print(("[Witcher] WC INSTUMENTATION DISABLED "));
    }

    if (getenv("NO_WC_EXTRA"))
    {
        wc_extra_instr = false;
        debug_print((" WC Extra Instrumentation DISABLED \n"));
    }
    else
    {
        debug_print((" \e[32m WC Extra Instrumentation ENABLED \e[0m\n"));
    }
    top_pid = getpid();
    cgi_get_shm_mem(SHM_ENV_VAR);

    char *id_str = getenv(SHM_ENV_VAR);
    prefork_cgi_setup();
    if (id_str)
    {
        afl_forkserver();
        debug_print(("[\e[32mWitcher\e[0m] Returning with pid %d \n\n", getpid()));
    }
    // setup cgi must be after fork
    setup_cgi_env();

    // fflush(stdout);
}

void witcher_cgi_trace_finish()
{
    printf("witcher_cgi_trace_finish()\n");
    start_tracing = false;

    if (witcher_print_op)
    {
        char logfn[50];
        sprintf(logfn, "/tmp/trace-%s.dat", witcher_print_op);
        FILE *tout_fp = fopen(logfn, "a");
        setbuf(tout_fp, NULL);
        int cnt = 0;
        for (int x = 0; x < MAPSIZE; x++)
        {
            if (afl_area_ptr[x] > 0)
            {
                cnt++;
            }
        }
        fprintf(tout_fp, "BitMap has %d  \n", cnt);

        for (int x = 0; x < MAPSIZE; x++)
        {
            if (afl_area_ptr[x] > 0)
            {
                fprintf(tout_fp, "%04x ", x);
            }
        }
        fprintf(tout_fp, "\n");
        for (int x = 0; x < MAPSIZE; x++)
        {
            if (afl_area_ptr[x] > 0)
            {
                fprintf(tout_fp, " %02x  ", afl_area_ptr[x]);
            }
        }
        fprintf(tout_fp, "\n");

        // fprintf(logfile2,"\tAFTER match=%d afl=%d \n", matchcnt, afl_area_ptr[bitmapLoc]);

        fclose(tout_fp);
    }

    op = 0;
    last = 0;
    trace_index = 0;
}

/*
void vld_start_trace(){
    printf("vld_start_trace()\n");

    if (getenv("WITCHER_PRINT_OP")){
        char tracefn[50];
        sprintf(tracefn, "/tmp/trace-%s.dat", getenv("WITCHER_PRINT_OP"));
        FILE *ofile = fopen(tracefn, "w");
        fclose(ofile);
    }
}

void vld_external_trace(zend_execute_data *execute_data, const zend_op *opline){
    printf("vld_external_trace()\n");
    FILE *ofile = NULL;

    if (witcher_print_op){
        const char *opname = zend_get_opcode_name(opline->opcode);
        char tracefn[50];
        sprintf(tracefn, "/tmp/trace-%s.dat", witcher_print_op);
        ofile = fopen(tracefn, "a");
        debug_print(("%d] %s (%d)   %d    %d \n",opline->lineno, opname, opline->opcode, opline->op1_type, opline->op2_type));
        fprintf(ofile, "%d] %s (%d)   %d    %d \n",opline->lineno, opname, opline->opcode, opline->op1_type, opline->op2_type);
    }

    if (start_tracing) {

        op = (opline->lineno << 8) | opline->opcode ; //opcode; //| (lineno << 8);

        if (last != 0) {
            int bitmapLoc = (op ^ last) % MAPSIZE;

            // turned off to disable afl code tracing
            afl_area_ptr[bitmapLoc]++;
        }
    }
    last = op;

    if (ofile){
        fflush(ofile);
        fclose(ofile);
    }
}
*/

typedef struct _save_value
{
    uint8_t type;
    uint32_t value;
} save_value;

typedef struct _trace_parameter
{
    save_value result;
    char *str_nm;
    char *type_pr;
    int is_check;
} trace_parameter;

typedef struct _web_trace
{
    char *parameter_str;
    int value;
    int check[2048];
    int is_trace;

    trace_parameter tp;

    int loop_len;
    save_value loop[512];

} web_trace;

#define str_witcher_print_op "tracetest"
static bool trace_run = false;
static zend_op *test = NULL;

static int wt_len;
static web_trace wt[512];

static trace_parameter is_parameter;

static int enter_func;

static int enter_func_check_length;
static int enter_func_check[128]; // 트레이싱하는것들 중에 무엇무엇이 들어있는지..

static int enter_func_sv_length;
static save_value enter_func_sv[sizeof(enter_func_check) * 3]; // 정보들을 모두 저장

static bool global_print;

static return_count;

static int check_u_func;

static save_value new_ret;

// 트레이싱 할 함수 리스트
static const char *trace_funcs[] = {
    "mysqli_query", "mysqli_multi_query",
    "query", "exec",
    "prepare", "query",
    "pg_execute", "pg_query", "pg_query_params",
    "find", "findOne", "findAndModify", "drop", "insert", "update",
    "file_get_contents", "curl_exec", "file",
    "move_uploaded_file", "copy",
    "readfile",
    "unlink",
    "addslashes"};

static int index_trace_func;

void vld_start_trace()
{
    //printf(" reset files \n");
    {
        FILE *file = fopen("/tmp/dict.txt", "w");
        if (file)
            close(file);

        file = fopen("/tmp/trace.txt", "w");
        if (file)
            close(file);
    }

    index_trace_func = 0;
    return_count = 0;
    global_print = false;
    check_u_func = 0;

    enter_func = 0;
    wt_len = 0;
    memset(&is_parameter, 0, sizeof(trace_parameter));

    if (getenv("START_TRACE"))
        trace_run = true;

    // printf("vld_start_trace()\n");

    if (afl_area_ptr == NULL)
    {
        if (getenv(SHM_ENV_VAR))
        {
            int shm_id = atoi(getenv(SHM_ENV_VAR));
            afl_area_ptr = shmat(shm_id, NULL, 0);
        }
    }

    char tracefn[50];
    sprintf(tracefn, "/tmp/trace-%s.dat", str_witcher_print_op);
    FILE *ofile = fopen(tracefn, "w");
    fclose(ofile);
}

void printLineFromFile(const char *filename, int lineNumber)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        printf("파일을 열 수 없습니다.\n");
        return;
    }

    char buffer[1000]; // 적절한 버퍼 크기를 선택하세요
    int lineCount = 0;

    while (fgets(buffer, sizeof(buffer), file) != NULL)
    {
        lineCount++;
        if (lineCount == lineNumber)
        {
            printf("라인 %d: %s\n", lineNumber, buffer);
            break;
        }
    }

    fclose(file);
}

/*
    참고 사이트

    zend_op 크기를 줄여 64비트 성능을 향상시켰습니다.
    https://externals.io/message/79523
    https://gist.github.com/dstogov/fba2cc621ef121826efe

    https://opensource.apple.com/source/apache_mod_php/apache_mod_php-148/php/Zend/zend_inheritance.c.auto.html
*/
#define CT_CONSTANT_EX(op_array, num) \
    ((op_array)->literals + (num))

#define CT_CONSTANT(node) \
    CT_CONSTANT_EX(CG(active_op_array), (node).constant)

#define CRT_CONSTANT_EX(op_array, opline, node)                                    \
    (((op_array)->fn_flags & ZEND_ACC_DONE_PASS_TWO) ? RT_CONSTANT(opline, (node)) \
                                                     : CT_CONSTANT_EX(op_array, (node).constant))

#define CRT_CONSTANT(node) \
    CRT_CONSTANT_EX(op_array, opline, node)

#define ZEND_CALL_VAR(call, n) \
    ((zval *)(((char *)(call)) + ((int)(n))))

#define EX_VAR(n) ZEND_CALL_VAR(execute_data, n)

#define ZEND_FETCH_R 80
#define ZEND_FETCH_DIM_R 81
#define ZEND_ASSIGN 22

#define ZEND_NEW 68
#define ZEND_SEND_VAR_EX 66
#define ZEND_DO_FCALL 60

#define ZEND_INIT_FCALL 61
#define ZEND_SEND_VAR 117
#define ZEND_DO_ICALL 129
#define ZEND_DO_UCALL 130 // 유저가 만든 함수 call

#define ZEND_RETURN 62

void vld_external_trace(zend_execute_data *execute_data, const zend_op *opline)
{
    if (trace_run == true)
    {
        bool print = false;

        FILE *ofile = NULL;

        const char *opname = zend_get_opcode_name(opline->opcode);

        char tracefn[50];
        sprintf(tracefn, "/tmp/trace-%s.dat", str_witcher_print_op);
        ofile = fopen(tracefn, "a");
        if (ofile == NULL)
            debug_print(("!!!!!\n"));

        // 현재 opline
        // debug_print(("\n%d] %s (%d)   %lx:%lx    %lx:%lx      %lx:%lx\n", opline->lineno, opname, opline->opcode, opline->op1_type, opline->op1.var, opline->op2_type, opline->op2.var, opline->result_type, opline->result.var));

        // printf("%d, %d\n", execute_data->opline->opcode, opline->opcode);

        if (global_print)
            printf("%s[%d](%d[%d], %d[%d]) => %d[%d]\n",
                   opname, opline->opcode,
                   opline->op1, opline->op1_type,
                   opline->op2, opline->op2_type,
                   opline->result, opline->result_type);

        switch (opline->opcode)
        {
        case ZEND_FETCH_DIM_R:
            // 그 타입이면..
            if (execute_data->opline->opcode == ZEND_FETCH_R)
            {
                /*
                    ZEND_FETCH_R[80](896[1], -1[0]) => 160[2]
                    ZEND_FETCH_DIM_R[81](160[2], 880[1]) => 176[2]
                */

                // printf("\t\t\t ===== Parameter ===== \n");
                if (execute_data->opline->op1_type == 1)
                {
                    is_parameter.is_check = 1;
                    is_parameter.result.type = opline->result_type;
                    is_parameter.result.value = opline->result.var;

                    is_parameter.str_nm = ((zval *)((char *)opline + opline->op2.var))->value.str->val;
                    is_parameter.type_pr = ((zval *)((char *)execute_data->opline + execute_data->opline->op1.var))->value.str->val;

                    printf("\t\t\t\t인자값 추출 %s[\'%s\']\n",
                           is_parameter.type_pr,
                           is_parameter.str_nm);

                    // TODO [ DICT.txt 파일로 내보내기? ]
                    FILE *file = fopen("/tmp/dict.txt", "a");
                    if (file == NULL)
                    {
                        printf("can't open file\n");
                    }
                    else
                    {
                        // printf("wrote...\n");
                        fprintf(file, "%s %s\n", is_parameter.type_pr, is_parameter.str_nm);
                        fclose(file);
                    }
                }
                // printf("\t\t\t ===================== \n");
            }
            break;

        case ZEND_ASSIGN:
            // 파라미터 할당 추적
            if (is_parameter.is_check == 1)
            {
                if (opline->op2.var == is_parameter.result.value)
                {
                    wt[wt_len].tp = is_parameter;

                    wt[wt_len].loop[wt[wt_len].loop_len].type = opline->op1_type;
                    wt[wt_len].loop[wt[wt_len].loop_len].value = opline->op1.var;

                    wt[wt_len].loop_len++;
                    wt[wt_len].is_trace = true;

                    wt_len++;
                    is_parameter.is_check = 0;
                }
            }
            break;

        // 함수 진입 확인
        case ZEND_NEW: // NEW의 경우 NEW에 리턴 값이 참조해야되는 값임
            enter_func = 3;

            new_ret.type = opline->result_type;
            new_ret.value = opline->result.var;
            break;

        case ZEND_INIT_FCALL:
            enter_func = 1;

            // 무슨 함수인가?
            // printf("\t\t\t ==================\n");
            // printf("\t\t\t == 함수 타입 : %d\n", ((zval *)((char *)opline + opline->op2.var))->u1.v.type);
            if (((zval *)((char *)opline + opline->op2.var))->u1.v.type != IS_STRING)
            {
                break;
            }

            // printf("\t\t\t == 함수 호출 : %s\n", ((zval *)((char *)opline + opline->op2.var))->value.str->val);
            // printf("\t\t\t == size : %d\n", ((zval *)((char *)opline + opline->op2.var))->value.str->len);

            // addslashes
            // [TODO] 문자열 집합으로 비교해야함 - 임시 방편 addslashes
            // 무엇을 타겟?    https://github1s.com/BoB-WebFuzzing/WTFuzzer-PHP/blob/master/hook.php#L1-L148

            int num_tr_func = sizeof(trace_funcs) / sizeof(trace_funcs[0]);
            // printf("\tnum_tr_func : %d\n", num_tr_func);

            bool check = true;

            for (int cur = 0; cur < num_tr_func; cur++)
            {
                check = true;

                char *check_str = trace_funcs[cur];
                size_t check_str_len = strlen(check_str);
                // printf("\t\t%s(%d)\n", check_str, check_str_len);

                if (((zval *)((char *)opline + opline->op2.var))->value.str->len == check_str_len)
                {
                    for (int i = 0; i < check_str_len; i++)
                    {
                        //  printf("\t\t\t %c\n", ((zval *)((char *)opline + opline->op2.var))->value.str->val[i]);

                        if (check_str[i] != ((zval *)((char *)opline + opline->op2.var))->value.str->val[i])
                            check = false;
                        // if (check_str[i] == ((zval *)((char *)opline + opline->op2.var))->value.str->val[i])
                        // {
                        //     printf("\t\t\t\t OK\n");

                        // }
                        // else
                        // {
                        //      printf("\t\t\t\t NO\n");
                        //     check = false;
                        // }
                    }

                    // printf("\t\t\t ==================\n");
                }
                else
                {
                    check = false;
                }

                if (check)
                {
                    enter_func = 2;
                    index_trace_func = cur;
                    printf("\t\t\t\t == %s 탐지 == \n", trace_funcs[index_trace_func]);
                    break;
                }
            }

            break;

        case ZEND_SEND_VAR_EX: //  NEW

            // NEW RET이 어느 파라미터에 참조되는가..
            if (enter_func == 3)
            {
                for (int i = 0; i < wt_len; i++)
                {
                    for (int j = 0; j < wt[i].loop_len; j++)
                    {
                        if (
                            (wt[i].loop[j].type == opline->op1_type) &&
                            (wt[i].loop[j].value == opline->op1.var))
                        {
                            // 한번더 등록되는 경우가 있음
                            bool check_duplicates = false;
                            for (int z = j; z < wt[i].loop_len; z++)
                            {
                                if (
                                    (wt[i].loop[z].type == new_ret.type) &&
                                    (wt[i].loop[z].value == new_ret.value))
                                {
                                    check_duplicates = true;
                                }
                            }

                            // 중복 X
                            if (!check_duplicates)
                            {
                                wt[i].loop[wt[i].loop_len].type = new_ret.type;
                                wt[i].loop[wt[i].loop_len].value = new_ret.value;
                                wt[i].loop_len++;
                            }
                        }
                    }
                }
            }

            break;
        case ZEND_SEND_VAR:
            // printf("ZEND_SEND_VAR 진입 %d \n", enter_func);
            if (enter_func == 1)
            {
                // 0 2 4 -> op1
                enter_func_sv[enter_func_sv_length].type = opline->op1_type;
                enter_func_sv[enter_func_sv_length].value = opline->op1.var;
                enter_func_sv_length++;

                // 1 3 5 -> ret
                enter_func_sv[enter_func_sv_length].type = opline->result_type;
                enter_func_sv[enter_func_sv_length].value = opline->result.var;
                enter_func_sv_length++;
            }
            else if (enter_func == 2)
            {
                // trace 확인 해야함
                bool final_check = false;
                web_trace *wt_tmp = (web_trace *)malloc(wt_len * sizeof(web_trace));
                int wt_tmp_len = 0;
                for (int i = 0; i < wt_len; i++)
                {
                    for (int j = 0; j < wt[i].loop_len; j++)
                    {
                        // //printf("%x == %x\n%x == %x\n",
                        //        wt[i].loop[j].type, opline->op1_type,
                        //        wt[i].loop[j].value, opline->op1.var);

                        if (
                            (wt[i].loop[j].type == opline->op1_type) &&
                            (wt[i].loop[j].value == opline->op1.var))
                        {
                            // printf("check! %s \n", wt[i].tp.str_nm);
                            wt_tmp[wt_tmp_len] = wt[i];
                            wt_tmp_len++;

                            wt[i].is_trace = false;
                            final_check = true;
                        }
                    }
                }

                if (final_check)
                {
                    for (int i = 0; i < wt_tmp_len; i++)
                    {
                        printf("\t\t\t======================================\n");
                        printf("\t\t\t======================================\n");
                        printf("\t\t\t\t%s[\'%s\'] trace done.\n", wt_tmp[i].tp.type_pr, wt_tmp[i].tp.str_nm);
                        printf("\t\t\t\t\t func: %s\n", trace_funcs[index_trace_func]);
                        printf("\t\t\t======================================\n");
                        printf("\t\t\t======================================\n");

                        // [TODO] 파일로 내보내기?
                        FILE *file = fopen("/tmp/trace.txt", "a");
                        if (file == NULL)
                        {
                            printf("can't open file\n");
                        }
                        else
                        {
                            // printf("wrote...\n");
                            fprintf(file, "%s %s %s\n", wt_tmp[i].tp.type_pr, wt_tmp[i].tp.str_nm, trace_funcs[index_trace_func]);
                            fclose(file);
                        }

                        // 추적 종료?
                        // wt_tmp[i].loop_len=0;
                    }
                }

                free(wt_tmp);
            }
            break;

        case ZEND_DO_FCALL: // NEW
            return_count++;
            enter_func = 0;
            break;
        case ZEND_DO_ICALL:
            // 정리
            if (enter_func == 1)
            {
                // printf("enter_func = 1\n");
                for (int e = 0; e < enter_func_sv_length; e++)
                {
                    for (int i = 0; i < wt_len; i++)
                    {
                        bool loop_check = false;
                        for (int j = 0; j < wt[i].loop_len; j++)
                        {
                            if ((enter_func_sv[e].type == wt[i].loop[j].type) && (enter_func_sv[e].value == wt[i].loop[j].value))
                            {
                                loop_check = true;
                            }
                        }
                        if (loop_check)
                        {
                            print = true;
                            wt[i].loop[wt[i].loop_len].type = opline->result_type;
                            wt[i].loop[wt[i].loop_len].value = opline->result.var;
                            wt[i].loop_len++;
                        }
                    }
                }
            }

            enter_func = 0;
            enter_func_check_length = 0;
            enter_func_sv_length = 0;
            break;

        // [TODO] ZEND_DO_UCALL 일때
        // 내부도 추적할 수 있어야 함..
        case ZEND_DO_UCALL:
            // ZEND_DO_ICALL과 같은 동작을 해야함 ( ZEND_SEND_VAL 추적 )

            if (enter_func == 1)
            {
                // printf("enter_func = 1\n");

                // + 리턴 값도 추가해야 함
                int is_add_return = 0;
                for (int e = 0; e < enter_func_sv_length; e = e + 2)
                {
                    for (int i = 0; i < wt_len; i++)
                    {
                        bool loop_check = false;
                        for (int j = 0; j < wt[i].loop_len; j++)
                        {
                            if ((enter_func_sv[e].type == wt[i].loop[j].type) && (enter_func_sv[e].value == wt[i].loop[j].value))
                            {
                                is_add_return = i;
                                loop_check = true;
                            }
                        }
                        if (loop_check)
                        {
                            print = true;
                            // ZEND_SEND_VAR의 리턴 값도 넣어야 함
                            // -> e의 홀수 + 1에 자리 하고 있음
                            if (is_add_return == i)
                            {

                                // 짝수 0, 2, 4, 6 -> op1
                                if ((e % 2) == 0)
                                {
                                    wt[i].loop[wt[i].loop_len].type = enter_func_sv[e + 1].type;
                                    wt[i].loop[wt[i].loop_len].value = enter_func_sv[e + 1].value;
                                    wt[i].loop_len++;
                                }
                                else
                                {
                                    printf("e가 홀수임. 문제 발생. 형빈 호출 필요 \n");
                                }

                                is_add_return++;
                            }
                            wt[i].loop[wt[i].loop_len].type = opline->result_type;
                            wt[i].loop[wt[i].loop_len].value = opline->result.var;
                            wt[i].loop_len++;
                        }
                    }
                }
            }

            enter_func = 0;
            enter_func_check_length = 0;
            enter_func_sv_length = 0;
            // ==

            // UCALL의 경우 사용자가 만든 function에 진입 -> 트레이싱이 가능해짐 -> Return 카운터를 증가시켜서 Depth를 증가시켜야함
            return_count++;

            // ZEND_DO_UCALL 의 반환 값이 결국 나중에 있을 Return의 반환값임.
            check_u_func = 1; // Return에서의 값을 추적해야함 -> Return의 반환 값이 ZEND_DO_UCALL의 반환 값이기 때문

            // 리턴 값을 추적해야 함.

            break;

        case ZEND_RETURN:

            // ZEND_DO_UCALL 리턴 값과 매칭?
            if (check_u_func > 0 && return_count > 0)
            {
                // 할 필요가 없을듯
                // 어차피 RETURN에 반환된 RET값은 사용되지 않고
                // ZEND_DO_UCALL 리턴 값이 사용됨.
                check_u_func = 0;
            }

            // 트레이싱 초기화
            if (return_count == 0)
            {
                memset(wt, 0, sizeof(wt));
                wt_len = 0;
            }

            return_count--;
            break;
        }

        if (print && global_print)
        {
            printf("============= print =============\n");
            for (int i = 0; i < wt_len; i++)
            {
                if (wt[i].is_trace == true)
                {
                    printf("trace : %s %s\n", wt[i].tp.type_pr, wt[i].tp.str_nm);

                    for (int j = 0; j < wt[i].loop_len; j++)
                    {
                        printf("\t [%d][%d]\n", wt[i].loop[j].type, wt[i].loop[j].value);
                    }
                }
            }
            printf("============== end ==============\n");
            print = false;
        }

        // printf("==========================\n");
        for (int i = 0; i < wt_len; i++)
        {
            int arg_check = 0;
            for (int j = 0; j < wt[i].loop_len; j++)
            {
                // 이제부터 모든 opcode의 파라미터들을 감시해야함
                // op1

                if ((opline->op1_type != 0x0))
                {
                    if ((wt[i].loop[j].value == opline->op1.var) &&
                        wt[i].loop[j].type == opline->op1_type)
                    {
                        arg_check += (1 << 0);
                    }
                }

                // op2
                if ((opline->op2_type != 0x0))
                {
                    if ((wt[i].loop[j].value == opline->op2.var) &&
                        wt[i].loop[j].type == opline->op2_type)
                    {
                        arg_check += (1 << 1);
                    }
                }

                // ret
                if ((opline->result_type != 0x0))
                {
                    if ((wt[i].loop[j].value == opline->result.var) &&
                        wt[i].loop[j].type == opline->result_type)
                    {
                        arg_check += (1 << 2);
                    }
                }
            }

            print = true;
            // printf("%d\n", arg_check);
            switch (arg_check)
            {
            case 0:
                // printf("아무것도 없음\n");
                print = false;
                break;
            case 1: // op2, ret

                if ((opline->op2_type != 0x0))
                {
                    wt[i].loop[wt[i].loop_len].type = opline->op2_type;
                    wt[i].loop[wt[i].loop_len].value = opline->op2.var;
                    wt[i].loop_len++;
                }
                if ((opline->result_type != 0x0))
                {
                    wt[i].loop[wt[i].loop_len].type = opline->result_type;
                    wt[i].loop[wt[i].loop_len].value = opline->result.var;
                    wt[i].loop_len++;
                }

                break;
            case 2: // op1, ret
                if ((opline->op1_type != 0x0))
                {
                    wt[i].loop[wt[i].loop_len].type = opline->op1_type;
                    wt[i].loop[wt[i].loop_len].value = opline->op1.var;
                    wt[i].loop_len++;
                }
                if ((opline->result_type != 0x0))
                {
                    wt[i].loop[wt[i].loop_len].type = opline->result_type;
                    wt[i].loop[wt[i].loop_len].value = opline->result.var;
                    wt[i].loop_len++;
                }

                break;
            case 4: // op1, op2
                if ((opline->op2_type != 0x0))
                {
                    wt[i].loop[wt[i].loop_len].type = opline->op2_type;
                    wt[i].loop[wt[i].loop_len].value = opline->op2.var;
                    wt[i].loop_len++;
                }
                if ((opline->op1_type != 0x0))
                {
                    wt[i].loop[wt[i].loop_len].type = opline->op1_type;
                    wt[i].loop[wt[i].loop_len].value = opline->op1.var;
                    wt[i].loop_len++;
                }
                break;

            case 3: // ret
                if ((opline->result_type != 0x0))
                {
                    wt[i].loop[wt[i].loop_len].type = opline->result_type;
                    wt[i].loop[wt[i].loop_len].value = opline->result.var;
                    wt[i].loop_len++;
                }
                break;
            case 5: // op2
                if ((opline->op2_type != 0x0))
                {
                    wt[i].loop[wt[i].loop_len].type = opline->op2_type;
                    wt[i].loop[wt[i].loop_len].value = opline->op2.var;
                    wt[i].loop_len++;
                }
                break;
            case 6: // op1
                if ((opline->op1_type != 0x0))
                {
                    wt[i].loop[wt[i].loop_len].type = opline->op1_type;
                    wt[i].loop[wt[i].loop_len].value = opline->op1.var;
                    wt[i].loop_len++;
                }
                break;

            case 7:
                break;
            }
        }

        if (print && global_print)
        {
            printf("============= print =============\n");
            for (int i = 0; i < wt_len; i++)
            {
                if (wt[i].is_trace == true)
                {
                    printf("trace : %s %s\n", wt[i].tp.type_pr, wt[i].tp.str_nm);

                    for (int j = 0; j < wt[i].loop_len; j++)
                    {
                        printf("\t [%d][%d]\n", wt[i].loop[j].type, wt[i].loop[j].value);
                    }
                }
            }
            printf("============== end ==============\n");
            print = false;
        }

        // printf("\texecute_data : %x\n", execute_data);
        // printf("\texecute_data->call : %lx\n", execute_data->call);
        // printf("\texecute_data->prev : %lx\n", execute_data->prev_execute_data);
        // printf("\texecute_data->zval return : %lx\n", execute_data->return_value);

        zend_string *cv;
        zval *isok;
        zval *tmp_var;

        switch (opline->op1_type)
        {
        case IS_CV:
            cv = EX(func)->op_array.vars[EX_VAR_TO_NUM(opline->op1.var)];
            // printf("[1]. %s\n", ZSTR_VAL(cv));
            break;

        case IS_CONST:
            isok = (zval *)((char *)opline + opline->op1.var);
            switch (isok->u1.v.type)
            {
            case IS_STRING:
                // printf("[1]. %s\n", ZSTR_VAL(isok->value.str));
                break;
            case IS_LONG:
                // printf("[1]. %d\n", isok->value.lval);
                break;
            }
            break;

        default:
            break;
        }

        switch (opline->op2_type)
        {
        case IS_CV:
            cv = EX(func)->op_array.vars[EX_VAR_TO_NUM(opline->op2.var)];
            // printf("[2]. %s\n", ZSTR_VAL(cv));
            break;

        // -
        case IS_CONST:
            isok = (zval *)((char *)opline + opline->op2.var);
            switch (isok->u1.v.type)
            {
            case IS_STRING:
                // printf("[2]. %s\n", ZSTR_VAL(isok->value.str));
                break;
            case IS_LONG:
                // printf("[2]. %d\n", isok->value.lval);
                break;
            }
            break;

        default:
            break;
        }

        switch (opline->result_type)
        {
        case IS_CV:
            cv = EX(func)->op_array.vars[EX_VAR_TO_NUM(opline->result.var)];
            // printf("[R]. %s\n", ZSTR_VAL(cv));
            break;

        // -
        case IS_CONST:
            isok = (zval *)((char *)opline + opline->result.var);
            switch (isok->u1.v.type)
            {
            case IS_STRING:
                // printf("[R]. %s\n", ZSTR_VAL(isok->value.str));
                break;
            case IS_LONG:
                // printf("[R]. %d\n", isok->value.lval);
                break;
            }
            break;

        default:
            break;
        }

        // printf("\n\topline : %lx\n", opline);
        // // printf("\n\t&opline : %x\n", &opline);
        // printf("\texecute line : %lx\n", execute_data->opline);
        // printf("\thandler... : %lx\n", opline->handler);
        // printf("\tThis... : %lx\n", &execute_data->This);
        // printf("\tThis... : %u\n", execute_data->This.u1.v.type);
        // printf("extra_named_params... : %lx\n", execute_data->extra_named_params);
        // printf("symbol_table... : %lx\n", execute_data->symbol_table);

        // // printf("%x\n", sizeof(zend_object)); // 0x38

        // if (execute_data->func)
        // {
        //     printf("\t\t\t[+] %lx\n", execute_data->func);
        //     printf("\t\t\t\t[+] %lx\n", execute_data->func->op_array);
        //     if (execute_data->func->common.arg_info)
        //     {
        //         printf("\t\t\t[*] common.arg_info here !\n");
        //         if (execute_data->func->common.arg_info->name)
        //         {
        //             printf("\t\t\t\t[+] name : %s\n", execute_data->func->common.arg_info->name->val);
        //         }
        //     }
        // }

        // printf("=========================================\n");
        // // printf("extra_named_params??\n");
        // // zend_array *extra_named_params = execute_data->extra_named_params;
        // // if(extra_named_params){
        // //     printf("==extra here!!==\n");
        // //     printf("extra : %lx\n", extra_named_params);
        // //     // printf("\t flags : %x\n", extra_named_params->u.v.flags);
        // //     // printf("\tnNumUsed : %x\n", extra_named_params->nNumUsed);
        // //     // printf("\tnNumOfElements : %x\n", extra_named_params->nNumOfElements);
        // //     // printf("\tnTableSize : %x\n", extra_named_params->nTableSize);

        // //     printf("\t\t HASH_FLAG_STATIC_KEYS : %x\n", HASH_FLAG_STATIC_KEYS);
        // //     if (extra_named_params->arData)
        // //         for (int i = 0; i < extra_named_params->nNumUsed; i++)
        // //         {
        // //             printf("\t\t\t arData key : %s\n", extra_named_params->arData[i].key->val);
        // //         }
        // // }

        // printf("=========================================\n");
        // printf("GET print\n");
        // zend_array *symbol_table = execute_data->symbol_table;
        // if (symbol_table)
        // {
        //     printf("==symbol table==\n");
        //     printf("\tnNumUsed : %x\n", symbol_table->nNumUsed);
        //     printf("\tnNumOfElements : %x\n", symbol_table->nNumOfElements);
        //     printf("\tnTableSize : %x\n", symbol_table->nTableSize);

        //     printf("\t flags : %x\n", symbol_table->u.v.flags);

        //     printf("\t\t HASH_FLAG_STATIC_KEYS : %x\n", HASH_FLAG_STATIC_KEYS);
        //     if (symbol_table->arData)
        //         for (int i = 0; i < symbol_table->nNumUsed; i++)
        //         {
        //             Bucket *data = &symbol_table->arData[i];
        //             printf("\t\t\t arData key : %s\n", data->key->val);
        //             printf("\t\t\t Type : %x\n", data->val.u1.v.type);

        //             switch( data->val.u1.v.type){
        //                 case IS_STRING:
        //                     printf("\t\t\t\t str : %s\n", data->val.value.str->val);
        //                     break;

        //                 case IS_ARRAY:
        //                     //zend_array *in_arr = data->val.value.arr;

        //                     break;

        //             }
        //         }
        // }

        // /*
        // zend_dump_op_line(&EX(func)->op_array, NULL, EX(opline), ZEND_DUMP_LINE_NUMBERS, NULL);
        // */
        // printf("=========================================\n");
        // if (opline->op2_type == IS_CONST)
        // {
        //     printf("zval sizeof : %x\n", sizeof(zval));

        //     printf("op2.value(%d) / zval(%d) = %d\n", opline->op2.constant, sizeof(zval),opline->op2.constant / sizeof(zval));

        //     // zval *op = CRT_CONSTANT_EX(EX(func)->op_array, opline, opline->op2);

        //     // if(op){
        //     //     printf("1op??? type : %s\n", zend_get_type_by_const(op->u1.v.type));
        //     // }

        //     // if (
        //     //     opline->opcode == ZEND_SWITCH_LONG ||| opline->opcode == ZEND_SWITCH_STRING || opline->opcode == ZEND_MATCH)
        //     // {
        //     //     HashTable *jumptable = Z_ARRVAL_P(op);
        //     //     zend_string *key;
        //     //     zend_ulong num_key;
        //     //     zval *zv;
        //     //     ZEND_HASH_FOREACH_KEY_VAL(jumptable, num_key, key, zv)
        //     //     {
        //     //         if (key)
        //     //         {
        //     //             fprintf(stderr, " \"%s\":", ZSTR_VAL(key));
        //     //         }
        //     //         else
        //     //         {
        //     //             fprintf(stderr, " " ZEND_LONG_FMT ":", num_key);
        //     //         }
        //     //         if (b)
        //     //         {
        //     //             fprintf(stderr, " BB%d,", b->successors[n++]);
        //     //         }
        //     //         else
        //     //         {
        //     //             fprintf(stderr, " %04u,", (uint32_t)ZEND_OFFSET_TO_OPLINE_NUM(op_array, opline, Z_LVAL_P(zv)));
        //     //         }
        //     //     }
        //     //     ZEND_HASH_FOREACH_END();
        //     //     fprintf(stderr, " default:");
        //     // }
        //     // else
        //     // {
        //     //     zend_dump_const(op);
        //     // }
        // }

        //     printf("=========================================\n");

        //     zval *isok = (zval*)((char*)opline + opline->op2.var);

        //     printf("%lx + %lx\n", opline, opline->op2.var);
        //     printf("isok : %lx\n", isok);
        //     printf("\tisok .type : %d\n", isok->u1.v.type);

        //     zend_string *cv = EX(func)->op_array.vars[EX_VAR_TO_NUM(opline->op1.var)];
        //     if (cv)
        //     {
        //         printf("cv : %lx\n", cv);
        //         printf("===11cvcvcvcvcvcv===\n\t%s\n", ZSTR_VAL(cv));
        //     }

        //     cv = EX(func)->op_array.vars[EX_VAR_TO_NUM(opline->op2.var)];
        //     if (cv)
        //     {
        //         printf("===22cvcvcvcvcvcv===\n\t%s\n", ZSTR_VAL(cv));
        //     }

        //     /*
        //     # define CT_CONSTANT_EX(op_array, num) \
        //         ((op_array)->literals + (num))
        //     */
        //     // zval *zv = CT_CONSTANT_EX(&EX(func)->op_array, opline->op2.num);

        //     // 0x40

        //     // https://www.phpinternalsbook.com/php7/zvals/basic_structure.html

        //     printf("\t\t1. %x\n", opline->op2.var);
        //     printf("\t\t2. %x\n", EX_VAR_TO_NUM(opline->op2.var));

        //     printf("\t\t\t[*] last_literal : %x\n", EX(func)->op_array.last_literal);
        //     printf("\t\t\t[*] last_var : %x\n", EX(func)->op_array.last_var);

        //     zval *p = EX(func)->op_array.literals;
        //     zval *end = p + EX(func)->op_array.last_literal;
        //     // ADD_SIZE(sizeof(zval) * EX(func)->op_array.last_literal);
        //     int i = 0;
        //     while (p < end)
        //     {
        //         printf("p: %lx\n", p);
        //         printf("\t\t[%d]. %x\n", i++, p->u1.v.type);

        //         switch (p->u1.v.type)
        //         {
        //         case IS_STRING:
        //             printf("\t\t\tstr : (%d)%s\n", p->value.str->len, p->value.str->val);
        //             break;

        //         case IS_LONG:
        //             printf("\t\t\tstr : %d\n", p->value.lval);
        //             break;
        //         }

        //         p++;
        //     }

        //     // for (int i = 0; i < EX(func)->op_array.last_literal; i++)
        //     // {
        //     //     printf("\t\t %x\n", EX(func)->op_array.literals[i].u1.v.type);
        //     //     printf("\t\t\t%lx\n", &EX(func)->op_array.literals[i]);
        //     //     printf("\t\t\t%lx\n", EX(func)->op_array.literals[i]);
        //     //     switch (EX(func)->op_array.literals[i].u1.v.type)
        //     //     {
        //     //     case IS_VAR:
        //     //         printf("\t\t\ttmp type : %lx\n", EX(func)->op_array.literals[i].value.lval);
        //     //         break;
        //     //     case IS_STRING:
        //     //         printf("\t\tstr : %s\n", EX(func)->op_array.literals[i].value.str->val);
        //     //         break;
        //     //     default:
        //     //         printf("unknown\n");
        //     //         break;
        //     //     }
        //     // }

        //     // printf("\t\t\t[*]nNumOfElements : %x\n", EX(func)->op_array.static_variables->nNumOfElements);
        //     // printf("\t\t\t[*]nNumUsed : %x\n", EX(func)->op_array.static_variables->nNumUsed);

        //     // if(zv){
        //     //     printf("wow!\n");
        //     //     printf("\ttype : %x\n",zv->u1.v.type);
        //     //     printf("\ttype_flag : %x\n",zv->u1.v.type_flags);
        //     //     printf("\tvalue : %lx\n", zv->value);

        //     // }

        //     // if (test == NULL)
        //     // {
        //     //     test = opline;
        //     //     printf("%x : %x\n", test, opline);
        //     // }
        //     // zval *zv = RT_CONSTANT(test, opline->op1);
        //     // if (zv)
        //     // {
        //     //     printf("\t[*] Z_TYPE_P(zv) : %lx\n", Z_TYPE_P(zv));
        //     // }

        //     // cv++;
        //     // zval *test = cv;
        //     // if (test)
        //     // {
        //     //     printf("\t======\t%x\n", test->u1.v.type);
        //     // }

        //     // if (opline->op2_type == IS_CONST)
        //     // {
        //     //     printf("is ISCONST\n");
        //     //     zval *tmp = CT_CONSTANT_EX(&execute_data->func->op_array, opline->op2.constant);
        //     //     if (tmp)
        //     //     {
        //     //         printf("\ttmp OK\n");
        //     //         printf("tmp type : %x\n", Z_TYPE_P(tmp));
        //     //     }

        //     //     zval *val = CT_CONSTANT(opline->op2);
        //     //     if (val)
        //     //     {
        //     //         printf("\tval OK\n");
        //     //         printf("val type : %x\n", Z_TYPE_P(val));
        //     //     }
        //     // }

        //     // if (opline->op2_type == IS_CONST)
        //     // {
        //     //     zend_op *op2 = opline + opline->op2.jmp_offset;
        //     //     zend_string *constant_value = EX(func)->op_array.literals[op2->op2.constant]->val.str;
        //     //     printf("Constant value: %s\n", ZSTR_VAL(constant_value));
        //     // }
        //     // cv = EX(func)->op_array.vars[EX_VAR_TO_NUM(opline->op2.var)];
        //     // if (cv)
        //     // {
        //     //     printf("===22cvcvcvcvcvcv===\n\t%s\n", ZSTR_VAL(cv));
        //     // }

        //     // zval *zv;
        //     // zv = RT_CONSTANT(execute_data->extra_named_params, opline->op1);
        //     // printf("\t\t[1] Type as integer: %u\n", zv->u1.v.type);
        //     // printf("\t\t\tlen:%lx\n",zv->value.str->len);
        //     // printf("\t\t[1] Type as integer: %u\n", zv->u1.v.type_flags);
        //     // zv = RT_CONSTANT(execute_data->extra_named_params, opline->op2);
        //     // printf("\t\t[2] Type as integer: %u\n", zv->u1.v.type);
        //     // printf("\t\t[2] Type as integer: %u\n", zv->u1.v.type_flags);
        //     // zv = RT_CONSTANT(execute_data->extra_named_params, opline->result);
        //     // printf("\t\t[3] Type as integer: %u\n", zv->u1.v.type);
        //     // printf("\t\t[3] Type as integer: %u\n", zv->u1.v.type_flags);

        //     if (execute_data->call)
        //     {
        //         printf("\t\t\t[*] call here !\n");
        //     }

        //     if (execute_data->prev_execute_data)
        //     {
        //         printf("\t\t\t[*] prev_execute_data here !\n");
        //     }

        //     // if(zv.u1.v.type == IS_STRING){
        //     //     printf("\tstr : %s\n", &zv.value.str->val);
        //     //     printf("\tstr : %s\n", zv.value.str->val);
        //     // }

        //     // zend_object *tmp = RT_CONSTANT2(opline, opline->op1);
        //     // if(tmp){
        //     //     printf("type : %x\n", tmp->ce->type);
        //     //     printf("zval type : %x\n", tmp->properties_table->u1.v.type);
        //     // }

        //     // printf("%d\n", sizeof(zend_object));

        //     // char *test = (char *)opline; // opline을 char 포인터로 형변환

        //     // for (int i = 0; i < 16; i++)
        //     // {
        //     //     printf("%x\n", *test++); // 각 바이트를 1바이트씩 출력
        //     // }
        //     //     zval zv;
        //     //     zv = *RT_CONSTANT(opline, opline->op1);
        //     //     printf("zv : %x\n", &zv);

        //     //     if(zv.u1.v.type == IS_STRING){
        //     //         debug_print(("str : %s\n", &zv.value.str->val[0]));
        //     //     }else if(zv.u1.v.type == IS_CONST){
        //     //         debug_print(("val : %d\n", zv.value.))
        //     //     }
        //     // IS_OBJECT

        //     // if (zv)
        //     // {
        //     //     switch (opline->op1_type)
        //     //     {
        //     //     case IS_CV:
        //     //         if (Z_TYPE(zv) == IS_STRING)
        //     //         {
        //     //             char *str = Z_STRVAL(zv);
        //     //             debug_print(("\top1_str : %s\n", str));
        //     //         }
        //     //         else
        //     //         {
        //     //             debug_print(("\top1_zv_type : unknown(%d)\n", Z_TYPE(zv)));
        //     //         }
        //     //         break;
        //     //     case IS_CONST:
        //     //         if (Z_TYPE(zv) == IS_STRING)
        //     //         {
        //     //             char *str = Z_STRVAL(zv);
        //     //             debug_print(("\top1_str : %s\n", str));
        //     //         }
        //     //         else
        //     //         {
        //     //             debug_print(("\top1_zv_type : unknown(%d)\n", Z_TYPE(zv)));
        //     //         }
        //     //         break;
        //     //     default:
        //     //         debug_print(("\top1_type : %d\n", opline->op1_type));
        //     //         break;
        //     //     }
        //     // }

        //     // zv = RT_CONSTANT(opline, opline->op2);
        //     // if (zv)
        //     // {
        //     //     switch (opline->op2_type)
        //     //     {
        //     //     case IS_CV:
        //     //         if (Z_TYPE(zv) == IS_STRING)
        //     //         {
        //     //             char *str = Z_STRVAL_P(zv);
        //     //             debug_print(("\top2_str : %s\n", str));
        //     //         }
        //     //         else
        //     //         {
        //     //             debug_print(("\top2_zv_type : unknown(%d)\n", Z_TYPE(zv)));
        //     //         }
        //     //         break;
        //     //     default:
        //     //         debug_print(("\top2_type : %d\n", opline->op2_type));
        //     //         break;
        //     //     }
        //     // }

        //     // zv = RT_CONSTANT(opline, opline->result);
        //     // if (zv)
        //     // {
        //     //     switch (opline->result_type)
        //     //     {
        //     //     case IS_CV:
        //     //         if (Z_TYPE(zv) == IS_STRING)
        //     //         {
        //     //             char *str = Z_STRVAL_P(zv);
        //     //             debug_print(("\tresult_str : %s\n", str));
        //     //         }
        //     //         else
        //     //         {
        //     //             debug_print(("\tresult_zv_type : unknown(%d)\n", Z_TYPE(zv)));
        //     //         }
        //     //         break;
        //     //     default:
        //     //         debug_print(("\tresult_type : %d\n", opline->result_type));
        //     //         break;
        //     //     }
        //     // }

        //     // if(opline->op1_type == IS_CV)
        //     // {
        //     //     debug_print(("\n\t\t\tO?\n"));

        //     //     zval *zv;
        //     //     size_t len;

        //     //     zv = RT_CONSTANT(opline, opline->op1);

        //     //     debug_print(("opline addr : %x\n", opline));
        //     //     debug_print(("zval size : %d\n", sizeof(zval)));
        //     //     if(zv){
        //     //         debug_print(("\t\t\tOooOOOOoo?\n"));
        //     //         //debug_print(("\t\t\str  : %s\n", zv->value.str));
        //     //         debug_print(("\t\t\tcheck : %d\n", zv->u1.v.type));
        //     //     }

        //     //     zv = RT_CONSTANT(&opline, opline->op1);

        //     //     debug_print(("opline addr : %x\n", opline));
        //     //     debug_print(("zval size : %d\n", sizeof(zval)));
        //     //     if(zv){
        //     //         debug_print(("\t\t\tOooOOOOoo?\n"));
        //     //         //debug_print(("\t\t\str  : %s\n", zv->value.str));
        //     //         debug_print(("\t\t\tcheck : %d\n", zv->u1.v.type));
        //     //     }

        //     // }

        //     // // common 여부
        //     // if (execute_data->func)
        //     //     if (execute_data->func->common.attributes)
        //     //     {
        //     //         debug_print(("\tattributes OK\n"));
        //     //     }

        //     // if(execute_data->func->internal_function.function_name){
        //     //      debug_print(("\tinternal : %s\n", ZSTR_VAL(execute_data->func->internal_function.function_name)));
        //     // }

        //     // if(execute_data->func->internal_function.attributes){
        //     //     debug_print(("\tinter - attributes OK\n"));
        //     // }

        //     // if (execute_data->func->op_array.scope)
        //     // {
        //     //     debug_print(("\t scope O \n"));

        //     //     if (execute_data->func->op_array.scope->name)
        //     //         debug_print(("\t test %s\n", execute_data->func->op_array.scope->name->val));
        //     // }

        //     // if (EX(func) && EX(func)->op_array.filename)
        //     // {
        //     //     // #define EX(element) 			((execute_data)->element)
        //     //     // func -> execute_data->func
        //     //     debug_print(("\n%s:%d\n", ZSTR_VAL(EX(func)->op_array.filename), opline->lineno));

        //     //     printLineFromFile(ZSTR_VAL(EX(func)->op_array.filename), opline->lineno);
        //     //     debug_print(("line_start : %d\n", execute_data->func->op_array.line_start));
        //     //     debug_print(("line_end : %d\n", execute_data->func->op_array.line_end));
        //     //     if (execute_data->func->op_array.doc_comment)
        //     //         debug_print(("doc_comment : %s\n", ZSTR_VAL(execute_data->func->op_array.doc_comment)));

        //     //     debug_print(("\n%s:%d\n", ZSTR_VAL(execute_data->func->op_array.filename), opline->lineno));

        //     //     // if (execute_data->func->op_array.function_name)
        //     //     //     debug_print(("function name: %s\n", ZSTR_VAL(execute_data->func->op_array.function_name)));

        //     //     debug_print(("num_args : %d\n", execute_data->func->op_array.num_args));
        //     //     debug_print(("required_num_args : %d\n", execute_data->func->op_array.required_num_args));
        //     //     debug_print(("temporary : %d\n", execute_data->func->op_array.T));
        //     //     debug_print(("last var : %d\n", execute_data->func->op_array.last_var));
        //     //     debug_print(("last : %d\n", execute_data->func->op_array.last));
        //     //     debug_print(("num_dynamic_func_defs : %d\n", execute_data->func->op_array.num_dynamic_func_defs));

        //     //     int last_var = execute_data->func->op_array.last_var;

        //     //     if(execute_data->func->op_array.static_variables_ptr__ptr){
        //     //         debug_print(("static_variables OK\n"));
        //     //         debug_print(("nNumUsed : %d\n", execute_data->func->op_array.static_variables_ptr__ptr->nNumUsed));
        //     //         debug_print(("nNumOfElements : %d\n", execute_data->func->op_array.static_variables_ptr__ptr->nNumOfElements));
        //     //     }

        //     //     if(execute_data->func->op_array.attributes){
        //     //         debug_print(("attributes OK\n"));
        //     //         debug_print(("nNumUsed : %d\n", execute_data->func->op_array.attributes->nNumUsed));
        //     //     }

        //     //     debug_print(("last var : %d\n", last_var));
        //     //     if (last_var)
        //     //     {
        //     //         for(int i=0; i<last_var; i++){
        //     //             debug_print(("\tstr : %s\n", ZSTR_VAL(execute_data->func->op_array.vars[i])));
        //     //             //debug_print(("\thash : %x\n", execute_data->func->op_array.vars[i]->h));
        //     //         }
        //     //     }

        //     //     int last_literal = execute_data->func->op_array.last_literal;
        //     //     debug_print(("last_literal : %d\n", last_literal));
        //     //     if(last_literal){
        //     //         for(int i=0; i<last_literal;i++){
        //     //             debug_print(("\ttype : %x\n", execute_data->func->op_array.literals[i].u1.v.type));
        //     //             if(execute_data->func->op_array.literals[i].u1.v.type == IS_STRING){
        //     //                 debug_print(("\tstr : %s\n", execute_data->func->op_array.literals[i].value.str->val));
        //     //             }
        //     //         }
        //     //     }
        //     // }

        //     // zend_array *symbol_table = execute_data->func->op_array.static_variables;
        //     // if(symbol_table != NULL)
        //     // {
        //     //     zend_string *key;
        //     //     zval *value;

        //     //     int i=0;
        //     //     ZEND_HASH_FOREACH_STR_KEY_VAL(symbol_table, key, value)
        //     //     {
        //     //          debug_print(("\t======= looop %d ======\n", i++));
        //     //     }
        //     //     ZEND_HASH_FOREACH_END();
        //     // }
        //     // // // 이전 opline
        //     // // const zend_op *preopline = execute_data->opline;
        //     // // const char *preopname = zend_get_opcode_name(preopline->opcode);
        //     // // debug_print(("%d] %s (%d)   %d    %d \n", preopline->lineno, preopname, preopline->opcode, preopline->op1_type, preopline->op2_type));

        //     // // fprintf(ofile, "==============================\n");
        //     // // zend_execute_data *call = execute_data->call;
        //     // // if (call)
        //     // // {
        //     // //     fprintf(ofile, "call O\n");
        //     // //     zend_function *fbc = call->func;
        //     // //     if (fbc)
        //     // //     {
        //     // //         fprintf(ofile, "fbc O\n");
        //     // //         zend_string *fname2 = fbc->common.function_name;
        //     // //         if (fname2)
        //     // //         {
        //     // //             fprintf(ofile, "fname2 O\n");
        //     // //             fprintf(ofile, "FunctionName:%s\n", ZSTR_VAL(fname2));
        //     // //         }
        //     // //     }
        //     // // }

        //     // // zend_function *current_function = execute_data->func;

        //     // // check debug
        //     // // if (current_function)
        //     // // {
        //     // //     fprintf(ofile, "current_function O\n");

        //     // //     if (current_function->common.function_name)
        //     // //     {
        //     // //         fprintf(ofile, "len : %x\n", current_function->common.function_name->len);

        //     // //         fprintf(ofile, "str : %s\n", current_function->common.function_name->val);
        //     // //     }
        //     // //     else
        //     // //     {
        //     // //         fprintf(ofile, "common.function_name X \n");
        //     // //     }

        //     // //     zend_internal_function current_internal_funtion = execute_data->func->internal_function;

        //     // //     if (current_internal_funtion.function_name)
        //     // //     {
        //     // //         fprintf(ofile, "current_internal_funtion.function_name O\n");

        //     // //         fprintf(ofile, "len : %x\n", current_internal_funtion.function_name->len);

        //     // //         fprintf(ofile, "str : %s\n", current_internal_funtion.function_name->val);
        //     // //     }
        //     // //     else
        //     // //     {
        //     // //         fprintf(ofile, "current_internal_funtion.function_name X\n");
        //     // //     }
        //     // // }
        //     // // else
        //     // // {
        //     // //     fprintf(ofile, "current_function X\n");
        //     // // }

        //     // // // end

        //     // // if (current_function && current_function->common.function_name)
        //     // // {
        //     // //     fprintf(ofile, "Currently executing function: %s\n", ZSTR_VAL(current_function->common.function_name));
        //     // // }
        //     // // else
        //     // // {
        //     // //     fprintf(ofile, "Currently executing function: Unknown function\n");
        //     // // }

        //     // // fprintf(ofile, "============ zend_execute_data ======\n");
        //     // // fprintf(ofile, "============ zend_op =========\n");
        //     // // fprintf(ofile, "%d] %s (%d)   %d    %d \n", opline->lineno, opname, opline->opcode, opline->op1_type, opline->op2_type);

        //     // // // Print all members of _zend_op struct
        //     // // fprintf(ofile, "Line: %d\n", opline->lineno);
        //     // // fprintf(ofile, "Opcode: %s (%d)\n", opname, opline->opcode);
        //     // // fprintf(ofile, "Operand 1 type: %d\n", opline->op1_type);
        //     // // fprintf(ofile, "Operand 2 type: %d\n", opline->op2_type);

        //     // // debug_print(("=extra=\n"));
        //     // // if (execute_data && execute_data->extra_named_params)
        //     // // {
        //     // //     zend_array *tmp = execute_data->extra_named_params;
        //     // //     debug_print(("nNumUsed : %d\n", tmp->nNumUsed));
        //     // //     debug_print(("nNumOfElements : %d\n", tmp->nNumOfElements));
        //     // //     debug_print(("nTableSize : %d\n", tmp->nTableSize));
        //     // // }
        //     // // else
        //     // // {
        //     // //     debug_print(("execute_data or extra_named_params is NULL\n"));
        //     // // }

        //     // // debug_print(("=extra=\n"));

        //     // if (execute_data->prev_execute_data)
        //     // {
        //     //     debug_print(("execute_data->prev_execute_data\n"));
        //     //     zend_string *func_str = execute_data->prev_execute_data->func->common.function_name;
        //     //     uint32_t *func_num_args = execute_data->prev_execute_data->func->common.num_args;
        //     //     uint32_t *required_num_args = execute_data->prev_execute_data->func->common.required_num_args;

        //     //     if (func_str)
        //     //         debug_print(("func str : %s\n", func_str->val));
        //     //     if (func_num_args)
        //     //         debug_print(("func_num_args : %d\n", func_num_args));

        //     //     if (required_num_args)
        //     //         debug_print(("func_required : %d\n", required_num_args));
        //     // }

        //     // if (execute_data->func)
        //     // {
        //     //     debug_print(("execute_data->func\n"));
        //     //     zend_string *func_str = execute_data->func->common.function_name;
        //     //     uint32_t *func_num_args = execute_data->func->common.num_args;
        //     //     uint32_t *required_num_args = execute_data->func->common.required_num_args;

        //     //     if (func_str)
        //     //         debug_print(("func str : %s\n", func_str->val));
        //     //     if (func_num_args)
        //     //         debug_print(("func_num_args : %d\n", func_num_args));

        //     //     if (required_num_args)
        //     //         debug_print(("func_required : %d\n", required_num_args));
        //     // }

        //     // if (execute_data->call)
        //     // {
        //     //     debug_print(("execute_data->call\n"));
        //     //     zend_execute_data *tmp = execute_data->call;

        //     //     if (tmp->func)
        //     //     {
        //     //         debug_print(("tmp->func\n"));
        //     //         zend_string *func_str = tmp->func->common.function_name;
        //     //         uint32_t *func_num_args = tmp->func->common.num_args;
        //     //         uint32_t *required_num_args = tmp->func->common.required_num_args;

        //     //         if (func_str)
        //     //             debug_print(("func str : %s\n", func_str->val));
        //     //         if (func_num_args)
        //     //             debug_print(("func_num_args : %d\n", func_num_args));

        //     //         if (required_num_args)
        //     //             debug_print(("func_required : %d\n", required_num_args));
        //     //     }
        //     // }
        //     // debug_print(("op1 type : %d ", opline->op1_type));

        //     // if (opline->op1_type != IS_UNUSED)
        //     // {
        //     //     debug_print(("op1 : %x \t", opline->op1.var));

        //     //     // zval *tmp = opline->op1.var;
        //     //     // debug_print(("tmp type : %x | \t ", tmp->u1.v.type));

        //     //     // char key_str[20];                              // Assuming key won't exceed 20 characters when converted to string
        //     //     // snprintf(key_str, sizeof(key_str), "%d", opline->op1.var); // Convert integer key to string

        //     //     // zval *val;
        //     //     // if (executor_globals.zend_constants)
        //     //     // {
        //     //     //     zend_string *constant_name = zend_string_init(key_str, strlen(key_str), 0);
        //     //     //     if ((val = zend_hash_find(executor_globals.zend_constants, constant_name)) != NULL)
        //     //     //     {
        //     //     //         debug_print(("Constant: %s, Value: %d\n", key_str, Z_TYPE_P(val)));

        //     //     //     }
        //     //     //     else
        //     //     //     {
        //     //     //         debug_print(("Constant '%s' not found.\n", key_str));
        //     //     //     }
        //     //     //     zend_string_release(constant_name);
        //     //     // }
        //     //     // HashTable *tmp_constants = executor_globals.zend_constants;
        //     //     // if (tmp_constants)
        //     //     // {
        //     //     //     Bucket *tmp_bucket = tmp_constants->arData[opline->op1.var];
        //     //     // }

        //     //     // zval *var_value = compiler_globals.active_op_array->vars[opline->op1.var];
        //     //     // if (var_value != NULL)
        //     //     // {
        //     //     //     // 변수가 존재하면 처리합니다.
        //     //     //     switch (Z_TYPE_P(var_value))
        //     //     //     {
        //     //     //     case IS_STRING:
        //     //     //         // 문자열인 경우 처리
        //     //     //         printf("Variable at index %d is a string: %s\n", opline->op1.var, Z_STRVAL_P(var_value));
        //     //     //         break;
        //     //     //     case IS_LONG:
        //     //     //         // 정수인 경우 처리
        //     //     //         printf("Variable at index %d is an integer: %ld\n", opline->op1.var, Z_LVAL_P(var_value));
        //     //     //         break;
        //     //     //     // 다른 타입에 대한 처리 추가
        //     //     //     default:
        //     //     //         printf("Variable at index %d is of unknown type\n", opline->op1.var);
        //     //     //         break;
        //     //     //     }
        //     //     // }
        //     //     // else
        //     //     // {
        //     //     //     // 변수가 존재하지 않는 경우 처리
        //     //     //     printf("Variable at index %d does not exist\n", opline->op1.var);
        //     //     // }
        //     // }
        //     // debug_print(("| op2 type : %d ", opline->op2_type));
        //     // if (opline->op2_type != IS_UNUSED)
        //     // {
        //     //     debug_print(("op2 : %x \t", opline->op2.var));
        //     // }

        //     // debug_print(("| result type : %d ", opline->result_type));
        //     // if (opline->result_type != IS_UNUSED)
        //     // {
        //     //     debug_print(("result : %x |\t", opline->result.var));
        //     // }

        //     // // debug_print(("%d : %d\n", opline->lineno, execute_data->opline->lineno));

        //     // // if (execute_data->call)
        //     // //     if (execute_data->call->opline)
        //     // //         debug_print(("======11=====\n%x\n==========\n", execute_data->call->opline));

        //     // // if(execute_data->prev_execute_data)
        //     // //     if(execute_data->prev_execute_data->opline)
        //     // //         debug_print(("======22=====\n%x\n==========\n", execute_data->prev_execute_data->opline));

        //     // // if (execute_data->call)
        //     // //     if (execute_data->call->opline)
        //     // //         if (execute_data->call->opline->lineno)
        //     // //             debug_print(("%d : %d\n", opline->lineno, execute_data->call->opline->lineno));
        //     // // if (execute_data->prev_execute_data)
        //     // //     if (execute_data->prev_execute_data->opline)
        //     // //         if (execute_data->prev_execute_data->opline->lineno)
        //     // //             debug_print(("%d : %d\n", opline->lineno, execute_data->prev_execute_data->opline->lineno));
        //     // // // 호출한 자

        //     // // zend_execute_data *current = execute_data->call;
        //     // // if(current){
        //     // //     debug_print(("current O\n"));

        //     // // }

        //     // // zend_array *params = execute_data->extra_named_params;

        //     // // if (params != NULL)
        //     // // {
        //     // //     zend_string *key;
        //     // //     zval *value;

        //     // //     ZEND_HASH_FOREACH_STR_KEY_VAL(params, key, value)
        //     // //     {
        //     // //         if (key)
        //     // //         {
        //     // //             debug_print(("Parameter : %s, Value : %d\n", ZSTR_VAL(key), Z_TYPE_P(value)));
        //     // //         }
        //     // //         if(value){

        //     // //         }
        //     // //     }
        //     // //     ZEND_HASH_FOREACH_END();
        //     // // }

        //     // // if (opline->op1_type == IS_CONST)
        //     // // {
        //     // //     debug_print(("Value : %x\n", opline->op1.constant));
        //     // // }
        //     // // else if (opline->op1_type == IS_CV)
        //     // // {

        //     // //     if (opline->lineno > 0 && opline->lineno < 20)
        //     // //     {
        //     // //         debug_print(("Value : %x\n", opline->op1.var));
        //     // //         debug_print(("Value : %x\n", opline->op1.constant));

        //     // //         if (opline->op2_type != IS_UNUSED)
        //     // //         {
        //     // //             debug_print(("op2 : %x\n", opline->op2.var));
        //     // //         }

        //     // //         zend_array *symbol_table = execute_data->symbol_table;
        //     // //         debug_print(("symbol_table's nNumUsed : %d\n", symbol_table->nNumUsed));
        //     // //         debug_print(("symbol_table's nTableSize : %d\n", symbol_table->nTableSize));
        //     // //         debug_print(("symbol_table's nNumOfElements : %d\n", symbol_table->nNumOfElements));

        //     // //         Bucket *test = symbol_table->arData;
        //     // //         debug_print(("test : %s\n", test[0].key->val));

        //     // //         if(execute_data->func==NULL)debug_print(("shit\n"));
        //     // //         int *count = execute_data->func->op_array.last_var;
        //     // //         debug_print(("last_var : %d\n", *count));

        //     // //         zend_string *str = execute_data->func->op_array.vars[opline->op1.var];

        //     // //         if (str)
        //     // //         {
        //     // //             debug_print(("str : %s\n", str->val));
        //     // //         }
        //     // //         else
        //     // //         {
        //     // //             debug_print(("??\n"));
        //     // //         }

        //     // zend_array *symbol_table = execute_data->symbol_table;

        //     // zval *cv_value;
        //     // if ((cv_value = zend_hash_index_find(symbol_table, opline->op1.var)) != NULL)
        //     // {
        //     //     debug_print(("Z_TYPE_P(cv_value) : %d\n", Z_TYPE_P(cv_value)));
        //     //     switch (Z_TYPE_P(cv_value))
        //     //     {
        //     //     case IS_STRING:
        //     //         debug_print(("Found CV value: %s\n", Z_STRVAL_P(cv_value)));
        //     //         break;
        //     //     default:
        //     //         debug_print(("unknown\n"));
        //     //         break;
        //     //     }
        //     // }
        //     // else
        //     // {
        //     //     debug_print(("CV value not found\n"));
        //     // }

        //     // if ((cv_value = zend_hash_index_find(symbol_table, opline->op2.var)) != NULL)
        //     // {
        //     //     debug_print(("Z_TYPE_P(cv_value2) : %d\n", Z_TYPE_P(cv_value)));
        //     //     switch (Z_TYPE_P(cv_value))
        //     //     {
        //     //     case IS_STRING:
        //     //         debug_print(("Found CV value2: %s\n", Z_STRVAL_P(cv_value)));
        //     //         break;
        //     //     default:
        //     //         debug_print(("unknown2\n"));
        //     //         break;
        //     //     }
        //     // }
        //     // else
        //     // {
        //     //     debug_print(("CV value not found\n"));
        //     // }
        //     // //     }
        //     // // }

        //     // // zend_array *symbol_table = execute_data->symbol_table;

        //     // // if (symbol_table != NULL)
        //     // // {
        //     // //     zend_string *key;
        //     // //     zval *value;

        //     // //     ZEND_HASH_FOREACH_STR_KEY_VAL(symbol_table, key, value)
        //     // //     {
        //     // //         const char *var_name = key ? ZSTR_VAL(key) : "unknown";

        //     // //         switch (Z_TYPE_P(value))
        //     // //         {
        //     // //         case IS_UNDEF:
        //     // //             debug_print(("Variable %s: undefined\n", var_name));
        //     // //             break;
        //     // //         case IS_NULL:
        //     // //             debug_print(("Variable %s: NULL\n", var_name));
        //     // //             break;
        //     // //         case IS_TRUE:
        //     // //             debug_print(("Variable %s: true\n", var_name));
        //     // //             break;
        //     // //         case IS_FALSE:
        //     // //             debug_print(("Variable %s: false\n", var_name));
        //     // //             break;
        //     // //         case IS_LONG:
        //     // //             debug_print(("Variable %s: %ld\n", var_name, Z_LVAL_P(value)));
        //     // //             break;
        //     // //         case IS_DOUBLE:
        //     // //             debug_print(("Variable %s: %f\n", var_name, Z_DVAL_P(value)));
        //     // //             break;
        //     // //         case IS_STRING:
        //     // //             debug_print(("Variable %s: %s\n", var_name, Z_STRVAL_P(value)));
        //     // //             break;
        //     // //         case IS_ARRAY:
        //     // //         {
        //     // //             debug_print(("Variable %s: Array\n", var_name));

        //     // //             zval *sub_value;
        //     // //             zval *sub_key;

        //     // //             ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(value), zend_ulong index, sub_key, sub_value)
        //     // //             {
        //     // //                 if (sub_key)
        //     // //                 {
        //     // //                     // 문자열인 경우
        //     // //                     debug_print(("Z_TYPE_P : %d\n", Z_TYPE_P(sub_key)));
        //     // //                     if (Z_TYPE_P(sub_key) == IS_STRING)
        //     // //                     {
        //     // //                         debug_print(("  Key: %s, Value: ", Z_STRVAL_P(sub_key)));
        //     // //                     }
        //     // //                     else
        //     // //                     {
        //     // //                         // 문자열이 아닌 경우 (예: 숫자 키)
        //     // //                         debug_print(("  Key: %ld, Value: ", Z_LVAL_P(sub_key)));
        //     // //                     }
        //     // //                 }
        //     // //                 else
        //     // //                 {
        //     // //                     // 키가 없는 경우
        //     // //                     debug_print(("  Key: none, Value: "));
        //     // //                 }

        //     // //                 // 값을 출력
        //     // //                 switch (Z_TYPE_P(sub_value))
        //     // //                 {
        //     // //                 // 값에 따라 출력 방식 설정
        //     // //                 case IS_STRING:
        //     // //                     debug_print(("%s\n", Z_STRVAL_P(sub_value)));
        //     // //                     break;
        //     // //                 case IS_LONG:
        //     // //                     debug_print(("%ld\n", Z_LVAL_P(sub_value)));
        //     // //                     break;
        //     // //                 // 다른 타입에 대한 처리 추가
        //     // //                 default:
        //     // //                     debug_print(("unknown type\n"));
        //     // //                     break;
        //     // //                 }
        //     // //             }
        //     // //             ZEND_HASH_FOREACH_END();

        //     // //             break;
        //     // //         }
        //     // //         case IS_OBJECT:
        //     // //             debug_print(("Variable %s: Object\n", var_name));
        //     // //             break;
        //     // //         default:
        //     // //             debug_print(("Variable %s: unknown type\n", var_name));
        //     // //             debug_print(("Type : %d\n", Z_TYPE_P(value)));

        //     // //             break;
        //     // //         }
        //     // //     }
        //     // //     ZEND_HASH_FOREACH_END();
        //     // // }

        //     // // #define IS_UNUSED	0		/* Unused operand */
        //     // // #define IS_CONST	    (1<<0)
        //     // // #define IS_TMP_VAR	(1<<1)
        //     // // #define IS_VAR		(1<<2)
        //     // // #define IS_CV		(1<<3)	/* Compiled variable */

        //     // /*
        //     // if (opline->op1.constant != NULL)
        //     // {
        //     //     if (opline->op1.constant)
        //     //     {
        //     //         const char *str = (const char *)opline->op1.constant;
        //     //         int isString = 1;

        //     //         fprintf(ofile, "str : %x\n", str);
        //     //         fprintf(ofile, "str : %s\n", str);
        //     //         for (int i = 0;; ++i)
        //     //         {
        //     //             if (str[i] == '\0')
        //     //             {
        //     //                 break; // null 종료 문자열을 발견함
        //     //             }
        //     //             if (str[i] < 32 || str[i] > 126)
        //     //             {
        //     //                 isString = 0; // ASCII 문자 범위를 벗어난 것 발견, 문자열이 아님
        //     //                 break;
        //     //             }
        //     //         }

        //     //         if (isString)
        //     //         {
        //     //             fprintf(ofile, "opline->op1.constant is a string: %s\n", str);
        //     //         }
        //     //         else
        //     //         {
        //     //             fprintf(ofile, "opline->op1.constant is not a string\n");
        //     //         }
        //     //     }
        //     //     else
        //     //     {
        //     //         fprintf(ofile, "opline->op1.constant is NULL\n");
        //     //     }
        //     // }
        //     // */
        //     // // fprintf(ofile, "Result type: %d\n", opline->result_type);
        //     // // fprintf(ofile, "Handler: %p\n", opline->handler);
        //     // // fprintf(ofile, "Extended value: %u\n", opline->extended_value);

        op = (opline->lineno << 8) | opline->opcode; // opcode; //| (lineno << 8);

        int bitmapLoc = (op ^ last) % MAPSIZE;
        // printf("bitmapLoc : %x \n", bitmapLoc);

        // fprintf(ofile, "==============================\n");

        if (afl_area_ptr != NULL)
            afl_area_ptr[bitmapLoc]++;

        last = op;

        if (ofile)
        {
            fflush(ofile);
            fclose(ofile);
        }
    }
}
