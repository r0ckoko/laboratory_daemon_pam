#ifndef CONFIGER_H
#define CONFIGER_H

#define CONF_PATH "/etc/knocker.conf"

#define PIDFILE_KEY "pid_file"
#define SOCKET_KEY "srv_socket"
#define LOG_KEY "log_file"
#define LOG_SIZE_KEY "log_size"
#define DELIMITER '='
#define COMMENT '#'

#define HARD_LIMIT_LOG_SIZE 1024
#define HARD_LIMIT_DIGITS 4

extern char* pid_file;
extern char* srv_socket;
extern char* log_file;
extern int_fast32_t log_size;

enum CONF_PARAMS
{
  PIDFILE = 1,
  SOCKET = 2,
  LOG = 3,
  LOG_SIZE = 4
};

enum CONF_ERRORS
{
  BAD_FORMAT = -1,
  UKNOWN_PARAM = -2,
  DUPLICATE_PARAM = -3,
  BAD_VALUE = -4,
  EMPTY_VALUE = -5
};

void removeExtraSpacesAndTabs(char *str);
char* getParamValue(char* str, int_fast32_t* key);
int_fast32_t lazyValidationCheck(char *value, int_fast32_t key);
int_fast32_t setParamValue(char* value, int_fast32_t key);
int_fast32_t readConfiguration();

#endif // CONFIGER_H
