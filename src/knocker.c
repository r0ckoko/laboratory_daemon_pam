#include <sys/types.h>
#include <sys/stat.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "knocker.h"
#include "protocol.h"
#include "logger.h"
#include "configer.h"

volatile sig_atomic_t incoming_signal = 0;

void signalHandler(int32_t sig_num)
{
  incoming_signal = sig_num;
}

bool isAloneInstance()
{
  bool retult = true;
  int_fast32_t pid_file_d = open(pid_file, O_RDONLY);
  if (pid_file_d == -1)
  {
    return retult;
  }
  char str_pid[MAX_PID_DIGITS+1] = "";
  if (read(pid_file_d, str_pid, MAX_PID_DIGITS) == -1)
  {
    goto finally;
  }
  char* end_ptr = NULL;
  errno = 0;
  int64_t num_pid = strtol(str_pid, &end_ptr, 10);
  if ((errno == ERANGE || *end_ptr != '\0' || end_ptr == str_pid) ||
     (num_pid <= 0 || num_pid > PID_MAX_LIMIT))
  {
    goto finally;
  }
  if (kill((pid_t)num_pid, 0) == 0)
  {
    retult = false;
  }

finally:
  close(pid_file_d);
  return retult;
}

int_fast32_t createPidFile()
{
  int_fast32_t ret = 0;
  int_fast32_t pid_file_d = 0;
  ret = pid_file_d = open(pid_file, O_WRONLY| O_CREAT| O_TRUNC, S_IWUSR|S_IRUSR|S_IRGRP|S_IROTH);
  if ( ret == -1 )
  {
    errorLog(log_fd,"Creating or opening pidfile has been failed", "open");
    return ret;
  }
  struct flock pid_lock = {0};
  pid_lock.l_type = F_WRLCK;
  pid_lock.l_whence = SEEK_SET;
  ret = fcntl(pid_file_d, F_SETLKW, &pid_lock);
  if (ret == -1)
  {
    errorLog(log_fd,"Locking of pidfile has been failed", "fcntl");
    close(pid_file_d);
    return ret;
  }
  pid_t curr_pid = getpid();
  char str_pid[MAX_PID_DIGITS+1] = "";
  sprintf(str_pid, "%d", curr_pid);
  ret = write(pid_file_d,str_pid,strlen(str_pid));
  if (ret < 0)
  {
    errorLog(log_fd,"Writing pid to pidfile has been failed", "write");
    close(pid_file_d);
    return ret;
  }
  close(pid_file_d);
  return ret = 0;
}

void closeAllFiles()
{
  int_fast32_t max_files = sysconf(_SC_OPEN_MAX);
  for(int_fast32_t fd = 0; fd < ( max_files == -1 ? DEFAULT_MAX_OPEN : max_files ); ++fd)
  {
    if (fd != log_fd)
      close(fd);
  }
}

int_fast32_t demonization(void)
{
  int_fast32_t ret = 0;
  ret = openLog();
  if (ret != 0)
  {
    fprintf(stderr, "Opening log file has been failed\n");
    return ret;
  }
  pid_t pid = fork();
  if (pid == -1)
  {
    errorLog(log_fd,"Process demonization has been failed", "fork");
    return pid;
  }
  else if (pid == 0)
  {
    umask(0);
    ret = setsid();
    if (ret == -1)
    {
      errorLog(log_fd,"Process demonization has been failed", "setsid");
      return ret;
    }
    pid = fork();
    if (pid == -1)
    {
      errorLog(log_fd,"Process demonization has been failed","fork");
      return ret;
    }
    else if (pid)
    {
      exit(0);
    }
    ret = chdir("/");
    if (ret == -1)
    {
      errorLog(log_fd,"Process demonization has been failed","chdir");
      return ret;
    }

    cap_t caps  = cap_init();
    cap_value_t cap_list[3];
    cap_list[0] = CAP_CHOWN;
    cap_list[1] = CAP_DAC_OVERRIDE;
    cap_list[2] = CAP_FOWNER;
    ret = cap_set_flag(caps,CAP_EFFECTIVE,3,cap_list, CAP_SET);
    if (ret == -1)
    {
      errorLog(log_fd,"Process demonization has been failed","cap_set_flag");
      return ret;
    }
    ret = cap_set_flag(caps,CAP_PERMITTED,3,cap_list, CAP_SET);
    if (ret == -1)
    {
      errorLog(log_fd,"Process demonization has been failed","cap_set_flag");
      return ret;
    }
    ret = cap_set_proc(caps);
    if (ret == -1)
    {
      errorLog(log_fd,"Process demonization has been failed","cap_set_proc");
      return ret;
    }
    ret = prctl(PR_SET_KEEPCAPS,1,0,0,0);
    if (ret == -1)
    {
      errorLog(log_fd,"Process demonization has been failed","prctl");
      return ret;
    }
    cap_free(caps);

    struct passwd *pwd = getpwnam(DAEMON_ACCOUNT_NAME);
    if (pwd != NULL)
    {
      setuid(pwd->pw_uid);
    }
    ret = createPidFile();
    if (ret != 0)
    {
      return ret;
    }

    struct sigaction act;
    sigset_t sigset;
    act.sa_handler = signalHandler;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGSEGV);
    act.sa_mask = sigset;
    act.sa_flags = SA_ONSTACK;
    sigaction(SIGINT, &act, 0);
    sigaction(SIGTERM, &act, 0);
    sigaction(SIGSEGV, &act, 0);

    closeAllFiles();
    open("/dev/null",O_RDONLY);
    open("/dev/null",O_WRONLY);
    open("/dev/null",O_WRONLY);
  }
  else
  {
    exit(0);
  }
  return ret;
}

int_fast32_t initServer(Server *server)
{
  memset(server,0, sizeof(Server));
  int_fast32_t ret = 0;
  ret = unlink(srv_socket);
  if ( ret == -1 && errno != ENOENT)
  {
    errorLog(log_fd,"Server startup has been failed", "unlink");
    return ret;
  }
  server->srv_sock_d = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (server->srv_sock_d == -1 )
  {
    errorLog(log_fd,"Server startup has been failed", "socket");
    return ret;
  }
  server->srv_addr.sun_family = AF_UNIX;
  memmove(server->srv_addr.sun_path, srv_socket, sizeof(server->srv_addr.sun_path));
  server->sockaddr_len = sizeof(struct sockaddr_un);

  ret = bind(server->srv_sock_d,(struct sockaddr*)&server->srv_addr,server->sockaddr_len);

  if (ret == -1)
  {
    errorLog(log_fd,"Server startup has been failed", "bind");
    return ret;
  }
  ret = fcntl(server->srv_sock_d, F_SETFL, O_NONBLOCK);
  if (ret == -1)
  {
    errorLog(log_fd,"Server startup has been failed", "fcntl");
    return ret;
  }
  return ret;
}

int_fast32_t runServer()
{
  int_fast32_t ret = 0;
  ret = demonization();
  if (ret != 0)
  {
    goto finally;
  }
  errno = 0;
  Server server;
  ret = initServer(&server);
  if (ret != 0)
  {
    goto finally;
  }
  infoLog(log_fd,"Server has been successfully started");
  struct pollfd fds[1];
  fds[0].fd = server.srv_sock_d;
  fds[0].events = POLLIN;
  char login[MAX_BUFFER_SIZE-1] = "";
  char password[MAX_BUFFER_SIZE-1] = "";
  char new_password[MAX_BUFFER_SIZE-1] = "";
  int_fast32_t protocol_stage = 0;
  int_fast32_t request_type = 0;
  const char *current_client = NULL;
  while(true)
  {
    if (incoming_signal)
    {
      signalLog(log_fd,incoming_signal);
      break;
    }
    ret = poll(fds, 1, TIMEOUT);
    if (ret == -1 && errno != EINTR)
    {
      errorLog(log_fd,"Server has been crashed", "poll");
      break;
    }
    else if (fds[0].revents & POLLIN)
    {
      ret = recvfrom(server.srv_sock_d, server.buffer, MAX_BUFFER_SIZE, 0, (struct sockaddr*)&server.cli_addr,&server.sockaddr_len);
      if (ret == -1)
      {
        errorLog(log_fd,"Server has been crashed","recvfrom");
        break;
      }
      switch (protocol_stage)
      {
        case NULL_STEP:
          if (strncmp(server.buffer,HELLO_AUTH_MSG,strlen(server.buffer)) == 0)
          {
            memset(server.buffer,0,MAX_BUFFER_SIZE);
            strncpy(server.buffer,HELLO_ANS,MAX_BUFFER_SIZE);
            request_type = AUTH_REQ;
            protocol_stage = FIRST_STEP;
            current_client = server.cli_addr.sun_path;
          }
          else if (strncmp(server.buffer,HELLO_CHPASSWD_MSG,strlen(server.buffer)) == 0)
          {
            memset(server.buffer,0,MAX_BUFFER_SIZE);
            strncpy(server.buffer,HELLO_ANS,MAX_BUFFER_SIZE);
            request_type = CHPASSWD_REQ;
            protocol_stage = FIRST_STEP;
            current_client = server.cli_addr.sun_path;
          }
          else
          {
            memset(server.buffer,0,MAX_BUFFER_SIZE);
            strncpy(server.buffer,FAILED,MAX_BUFFER_SIZE);
          }
          break;

        case FIRST_STEP:
          if (strncmp(current_client,server.cli_addr.sun_path,strlen(server.cli_addr.sun_path)) == 0)
          {
            memset(login,0,sizeof(login));
            strncpy(login,server.buffer,sizeof(login));
            memset(server.buffer,0,MAX_BUFFER_SIZE);
            strncpy(server.buffer,PASS_REQ,MAX_BUFFER_SIZE);
            protocol_stage = SECOND_STEP;
          }
          else
          {
            memset(server.buffer,0,MAX_BUFFER_SIZE);
            strncpy(server.buffer,STAND_IN_LINE,MAX_BUFFER_SIZE);
          }
          break;

        case SECOND_STEP:
          if (strncmp(current_client,server.cli_addr.sun_path,strlen(server.cli_addr.sun_path)) != 0)
          {
            memset(server.buffer,0,MAX_BUFFER_SIZE);
            strncpy(server.buffer,STAND_IN_LINE,MAX_BUFFER_SIZE);
          }
          else if (request_type == AUTH_REQ)
          {
            memset(password,0,sizeof(password));
            strncpy(password,server.buffer,sizeof(password));
            memset(server.buffer,0,MAX_BUFFER_SIZE);
            int_fast16_t ret = auth(login,password);
            if (ret == 0)
            {
              strncpy(server.buffer,SUCCESS,MAX_BUFFER_SIZE);
              auditLog(log_fd,AUTH_OK,login);
            }
            else
            {
              int_fast16_t length = strlen(FAILED);
              strncpy(server.buffer,FAILED,MAX_BUFFER_SIZE);
              server.buffer[length] = ' ';
              server.buffer[length+1] = ret+'0';
              auditLog(log_fd,AUTH_FAIL,login);
            }
            protocol_stage = NULL_STEP;
          }
          else if (request_type == CHPASSWD_REQ)
          {
            memset(password,0,sizeof(password));
            strncpy(password,server.buffer,sizeof(password));
            memset(server.buffer,0,MAX_BUFFER_SIZE);
            strncpy(server.buffer,NEWPASS_REQ,MAX_BUFFER_SIZE);
            protocol_stage = THIRD_STEP;
          }
          else
          {
            protocol_stage = NULL_STEP;
          }
          break;

        case THIRD_STEP:
          if (strncmp(current_client,server.cli_addr.sun_path,strlen(server.cli_addr.sun_path)) != 0)
          {
            memset(server.buffer,0,MAX_BUFFER_SIZE);
            strncpy(server.buffer,STAND_IN_LINE,MAX_BUFFER_SIZE);
          }
          else if (request_type == CHPASSWD_REQ)
          {
            memset(new_password,0,sizeof(new_password));
            strncpy(new_password,server.buffer,sizeof(new_password));
            memset(server.buffer,0,MAX_BUFFER_SIZE);
            int_fast8_t ret = changePassword(login,password,new_password);
            if (ret == 0)
            {
              strncpy(server.buffer,SUCCESS,MAX_BUFFER_SIZE);
              auditLog(log_fd,CHANGE_PASSWD_OK,login);
            }
            else
            {
              int_fast16_t length = strlen(FAILED);
              strncpy(server.buffer,FAILED,MAX_BUFFER_SIZE);
              server.buffer[length] = ' ';
              if (ret/10 > 0)
              {
                server.buffer[length+1] = (ret/10)+'0';
                server.buffer[length+2] = (ret%10)+'0';
              }
              else server.buffer[length+1] = ret+'0';
              auditLog(log_fd,CHANGE_PASSWD_FAIL,login);
            }
          }
          protocol_stage = NULL_STEP;
          break;
      }
      ret = sendto(server.srv_sock_d, server.buffer, MAX_BUFFER_SIZE, 0, (struct sockaddr*)&server.cli_addr,server.sockaddr_len);
    }
  }

finally:
  unlink(pid_file);
  if (server.srv_sock_d != -1)
  {
    close(server.srv_sock_d);
    unlink(srv_socket);
  }

  return ret;
}
