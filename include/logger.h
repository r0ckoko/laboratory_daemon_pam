#ifndef LOGGER_H
#define LOGGER_H

#define TIMESTAMP_LEN 20
#define ERR_MSG_TYPE "[ERROR]"
#define INFO_MSG_TYPE "[INFO]"
#define AUDIT_MSG_TYPE "[AUDIT]"
#define STR_SIGTERM "SIGTERM"
#define STR_SIGINT "SIGINT"
#define STR_SIGSEGV "SIGSEGV"
#define UKNOWN_SIGNAL "UKNOWN"

extern int_fast32_t log_fd;

enum AUDIT_OP_CODES
{
  AUTH_OK = 1,
  AUTH_FAIL = 2,
  CHANGE_PASSWD_OK = 3,
  CHANGE_PASSWD_FAIL = 4
};

void getLogSize(void);
void errorLog(int_fast16_t log_fd,char* msg,char* crashed_funcs);
void infoLog(int_fast16_t log_fd, char* info_msg);
void signalLog(int_fast16_t log_fd, int_fast16_t signal);
void auditLog(int_fast16_t log_fd,int_fast16_t opcode,char* login);
int_fast32_t openLog(void);
void getCurrentTimeInStr(char* buffer);
void checkAndFixOversize(void);
#endif // LOGGER_H
