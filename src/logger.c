#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include "logger.h"
#include "configer.h"

int_fast32_t log_fd = -1;

int_fast32_t openLog()
{
  int_fast32_t ret = 0;
  bool isSizeLimitReached = false;
  struct stat log_stat = {0};
  ret = stat(log_file,&log_stat);
  if (ret == -1 && errno != ENOENT)
    return ret;
  else if ((log_stat.st_size/1024) > HARD_LIMIT_LOG_SIZE)
    isSizeLimitReached = true;
  log_fd = open(log_file, O_WRONLY | O_CREAT | (isSizeLimitReached == true ? O_TRUNC : O_APPEND), S_IRUSR | S_IWUSR);
  if (log_fd == -1)
    ret = log_fd;

  return ret;
}

void checkAndFixOversize()
{
  struct stat log_stat = {0};
  int_fast16_t ret = fstat(log_fd,&log_stat);
  if (ret == -1 && errno != ENOENT)
    return;
  else if ((log_stat.st_size/1024) > HARD_LIMIT_LOG_SIZE)
  {
    close(log_fd);
    log_fd = open(log_file, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  }
}

void getCurrentTimeInStr(char *buffer)
{
  time_t t;
  struct tm *tm;
  t = time(NULL);
  tm = localtime(&t);
  strftime(buffer,TIMESTAMP_LEN,"%d.%m.%Y %H:%M:%S",tm);
}

void errorLog(int_fast32_t log_fd, char *msg, char* crashed_func)
{
  checkAndFixOversize();
  char str_time[TIMESTAMP_LEN] = "";
  getCurrentTimeInStr(str_time);
  dprintf(log_fd,"[%s] %s %s\n",str_time,ERR_MSG_TYPE,msg);
  dprintf(log_fd,"\t`--- function %s failed [Code:%ld](%s)\n",crashed_func,errno, strerror(errno));
}

void infoLog(int_fast16_t log_fd, char *info_msg)
{
  checkAndFixOversize();
  char str_time[TIMESTAMP_LEN] = "";
  getCurrentTimeInStr(str_time);
  dprintf(log_fd,"[%s] %s %s\n",str_time,INFO_MSG_TYPE,info_msg);
}

void signalLog(int_fast16_t log_fd, int_fast16_t signal)
{
  checkAndFixOversize();
  char str_time[TIMESTAMP_LEN] = "";
  getCurrentTimeInStr(str_time);
  char *sig_str = '\0';
  switch (signal)
  {
    case SIGINT:
      sig_str = STR_SIGINT;
      break;
    case SIGTERM:
      sig_str = STR_SIGTERM;
      break;
    case SIGSEGV:
      sig_str = STR_SIGSEGV;
      break;
    default:
      sig_str = UKNOWN_SIGNAL;
      break;
  }
  dprintf(log_fd,"[%s] %s Server has been stopped by signal %s\n",str_time,INFO_MSG_TYPE,sig_str);
}

void auditLog(int_fast16_t log_fd,int_fast16_t opcode, char *login)
{
  checkAndFixOversize();
  char str_time[TIMESTAMP_LEN] = "";
  getCurrentTimeInStr(str_time);
  switch (opcode)
  {
    case AUTH_OK:
      dprintf(log_fd,"[%s] %s User %s authentication attempt completed successfully\n",str_time,AUDIT_MSG_TYPE,login);
      break;
    case AUTH_FAIL:
      dprintf(log_fd,"[%s] %s User %s authentication attempt failed\n",str_time,AUDIT_MSG_TYPE,login);
      break;
    case CHANGE_PASSWD_OK:
      dprintf(log_fd,"[%s] %s Change password for %s completed successfully\n",str_time,AUDIT_MSG_TYPE,login);
      break;
    case CHANGE_PASSWD_FAIL:
      dprintf(log_fd,"[%s] %s Change password for %s failed\n",str_time,AUDIT_MSG_TYPE,login);
      break;
  }
}
