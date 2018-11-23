#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "configer.h"

char* pid_file = NULL;
char* srv_socket = NULL;
char* log_file = NULL;
int_fast32_t log_size = 0;

void removeExtraSpacesAndTabs(char* str)
{
  char* ch = str;
  char* pos = str;
  while (*ch != '\0')
  {
    if (*ch != ' ' && *ch != '\t')
    {
      *pos = *ch;
      pos++;
    }
    ch++;
  }
  *pos = '\0';
}

char* getParamValue(char* str, int_fast32_t* key)
{
  char* ret = '\0';
  if (str[0] == DELIMITER)
  {
    *key = BAD_FORMAT;
    return ret;
  }
  char* ch = str;
  char* delim = NULL;
  while (*ch != '\0' && *ch != DELIMITER) ch++;
  if (*ch == '\0')
  {
    *key = BAD_FORMAT;
    return ret;
  }
  delim = ch;
  ch++;
  if (*ch == '\0')
  {
    *key = EMPTY_VALUE;
    return ret;
  }
  if (strncmp(str,PIDFILE_KEY,delim-str) == 0)
  {
    *key = PIDFILE;
    return ch;
  }
  else if (strncmp(str,SOCKET_KEY,delim-str) == 0)
  {
    *key = SOCKET;
    return ch;
  }
  else if (strncmp(str,LOG_KEY,delim-str) == 0)
  {
    *key = LOG;
    return ch;
  }
  else if (strncmp(str,LOG_SIZE_KEY,delim-str) == 0)
  {
    *key = LOG_SIZE;
    return ch;
  }
  else return ret;
}

int_fast32_t lazyValidationCheck(char *value, int_fast32_t key)
{
  int_fast32_t ret = 0;
  if (key == PIDFILE || key == SOCKET || key == LOG)
  {
    // Path must start from /
    if (value[0] != '/')
      ret = BAD_VALUE;
    // File can't finish /
    else if (value[strlen(value)-1] == '/')
      ret = BAD_VALUE;
  }
  else if (key == LOG_SIZE)
  {
    int_fast32_t len = strlen(value);
    if (len > HARD_LIMIT_DIGITS)
      ret = BAD_VALUE;
    else if (len != strspn(value,"0123456789"))
      ret = BAD_VALUE;
    else if (value[0] == '0')
      ret = BAD_VALUE;
  }
  else ret = UKNOWN_PARAM;

  return ret;
}

int_fast32_t setParamValue(char *value, int_fast32_t key)
{
//  !!!Attention!!!
// In this function occur memory allocation in heap
// To prevent leak memory don't forget to free this memory
// before program finished
  int_fast32_t ret = 0;
  switch (key)
  {
    case PIDFILE:
      if (pid_file != NULL)
      {
        ret = DUPLICATE_PARAM;
      }
      else
      {
        pid_file = strndup(value, strlen(value));
      }
      break;
    case SOCKET:
      if (srv_socket != NULL)
      {
        ret = DUPLICATE_PARAM;
      }
      else
      {
        srv_socket = strndup(value, strlen(value));
      }
      break;
    case LOG:
      if (log_file != NULL)
      {
        ret = DUPLICATE_PARAM;
      }
      else
      {
        log_file = strndup(value, strlen(value));
      }
      break;
    case LOG_SIZE:
      if (log_size != 0)
      {
        ret = DUPLICATE_PARAM;
      }
      else
      {
        int_fast32_t size = strtol(value, NULL,10);
        if (size == 0 || size > HARD_LIMIT_LOG_SIZE)
        {
          ret = BAD_VALUE;
        }
        else
        {
          log_size = size;
        }
      }
      break;
    default:
      break;
  }
  return ret;
}

int_fast32_t readConfiguration()
{
  FILE *conf_file = fopen(CONF_PATH,"r");
  if (conf_file == NULL)
  {
    fprintf(stderr, "Configuration file not found\n");
    return 1;
  }
  char line[255] = "";
  int_fast32_t ret = 0;
  while (fgets(line,sizeof(line),conf_file)!= NULL)
  {
    int_fast32_t len = strlen(line);
    if (len > 0 && line[0] != '\n')
    {
      if (line[len-1] == '\n')
      {
        line[len-1] = '\0';
      }
      removeExtraSpacesAndTabs(line);
      if (line[0] != COMMENT)
      {
        int_fast32_t key = 0;
        char* value = getParamValue(line,&key);
        if (key < 0)
        {
          ret = key;
          break;
        }
        ret = lazyValidationCheck(value,key);
        if (ret < 0)
        {
          break;
        }
        ret = setParamValue(value,key);
        if (ret < 0)
        {
          break;
        }
      }
    }
    memset(line,0,sizeof(line));
  }
  fclose(conf_file);
  return ret;
}
