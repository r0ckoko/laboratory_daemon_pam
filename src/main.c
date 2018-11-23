#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include "knocker.h"
#include "configer.h"
#include "logger.h"

int main(int argc, char const *argv[])
{
  uint_least8_t altstack_mem[SIGSTKSZ] = "";
  stack_t altstack = {0};
  altstack.ss_sp = altstack_mem;
  altstack.ss_size = SIGSTKSZ;
  altstack.ss_flags = SS_ONSTACK;
  sigaltstack(&altstack,NULL);
 
  if (readConfiguration() == 0)
  {
    if (isAloneInstance())
    {
      if (demonization() == 0)
      {
        runServer();
      }
    }
    else fprintf(stdout,"This daemon is already work\n");
  }
  if (log_fd != -1)
    close(log_fd);
  if (pid_file != NULL)
    free(pid_file);
  if (log_file != NULL)
    free(log_file);
  if (srv_socket != NULL)
    free(srv_socket);

  return 0;
}
