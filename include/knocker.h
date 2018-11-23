#ifndef KNOCKER_H
#define KNOCKER_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>

#define MAX_PID_DIGITS 7 // pid on 64-x operation system has max size limit ~ 4194304
#define PID_MAX_LIMIT 4194304
#define DEFAULT_MAX_OPEN 1024
#define MAX_BUFFER_SIZE 1024
#define DAEMON_ACCOUNT_NAME "easyauth"

extern volatile sig_atomic_t incoming_signal;

typedef struct T_Server
{
  int_fast32_t srv_sock_d;
  struct sockaddr_un srv_addr;
  struct sockaddr_un cli_addr;
  socklen_t sockaddr_len;
  uint_least8_t buffer[MAX_BUFFER_SIZE];
} Server;

static void signalHandler(int32_t sig_num);
bool isAloneInstance(void);
int_fast32_t createPidFile(void);
void closeAllFiles();
int_fast32_t demonization(void);
int_fast32_t runServer(void);

#endif // KNOCKER_H
