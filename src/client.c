#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "protocol.h"

int_fast8_t err_code = 0;
char str_err[MAX_STRERROR_LEN] = "";

int_fast32_t secureInput(char *password,int_fast32_t size, char *input_msg)
{
  int_fast32_t ret = 0;
  struct termios oldt, newt;
  ret = tcgetattr(STDIN_FILENO, &oldt);
  if (ret != 0)
  {
    fprintf(stderr,"Function tcgetattr() failed [Code:%d](%s)\n", errno, strerror(errno));
    return ret;
  }
  newt = oldt;
  newt.c_lflag &= ~ECHO;
  ret = tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  if (ret != 0)
  {
    fprintf(stderr,"Function tcgetattr() failed [Code:%d](%s)\n", errno, strerror(errno));
    return ret;
  }
  fprintf(stdout,"%s:",(strlen(input_msg) == 0 ? DEFAULT_INPUT_MESSAGE : input_msg));
  fgets(password, size-1, stdin);
  fprintf(stdout,"\n");
  int_fast16_t nl_index = strlen(password);
  if (nl_index > 1)
  {
    password[nl_index-1] = '\0';
  }
  ret = tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  if (ret != 0)
  {
    fprintf(stderr,"Function tcgetattr() failed [Code:%d](%s)\n", errno, strerror(errno));
    return ret;
  }

  return ret;
}

bool remoteAuth(char* srv_socket,char *login, char *password)
{
  bool auth_res = false;
  if (login == NULL || strlen(login) == 0)
  {
    fprintf(stderr,"The user's login can't be empty\n");
    return auth_res;
  }
  struct sockaddr_un srv_addr = {0};
  srv_addr.sun_family = AF_UNIX;
  memcpy(srv_addr.sun_path, srv_socket, strlen(srv_socket));
  int_fast16_t connect_sock_d = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (connect_sock_d == -1)
  {
    fprintf(stderr,"Function socket() failed [Code:%d](%s)\n", errno, strerror(errno));
    return auth_res;
  }
  struct sockaddr_un cli_addr = {0};
  cli_addr.sun_family = AF_UNIX;
  char temp_sock_name[sizeof(CLIENT_SOCKET_TEMPLATE)] = "";
  strncpy(temp_sock_name,CLIENT_SOCKET_TEMPLATE, sizeof(temp_sock_name));
  int_fast16_t sock_fd = 0;
  while ((sock_fd = mkstemp(temp_sock_name)) == -1 );
  close(sock_fd);
  memcpy(cli_addr.sun_path, temp_sock_name, sizeof(cli_addr.sun_path));
  socklen_t sockaddr_len = sizeof(struct sockaddr_un);
  // Remove socket if it already exist
  if (unlink(temp_sock_name) == -1 && errno != ENOENT)
  {
    fprintf(stderr,"Function unlink() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }
  // Set nonblocking mode
  if (fcntl(connect_sock_d, F_SETFL, O_NONBLOCK) == -1)
  {
    fprintf(stderr,"Function fcntl() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }
  // Bind address settings to created socket
  if (bind(connect_sock_d,(struct sockaddr*)&cli_addr,sockaddr_len) == -1)
  {
    fprintf(stderr,"Function bind() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }

  char buffer[MAX_BUFFER_SIZE] = "";
  struct pollfd fds[1];
  fds[0].fd = connect_sock_d;
  fds[0].events = POLLIN;
  int_fast32_t ret = 0;
  strncpy(buffer,HELLO_AUTH_MSG,strlen(HELLO_AUTH_MSG));
  // send hello message which init protocol
  if (sendto(connect_sock_d, buffer,MAX_BUFFER_SIZE, 0, (struct sockaddr*)&srv_addr,sockaddr_len) == -1)
  {
    if (errno == ENOENT)
    {
      fprintf(stderr,"Server not working\n");
    }
    else fprintf(stderr,"Function sendto() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }
  memset(buffer,0,MAX_BUFFER_SIZE); // clear buffer
  ret = poll(fds, 1, TIMEOUT);
  if (ret <= 0)
  {
    fprintf(stderr,"Server is not responsing\n");
    goto finally;
  }
  // get response and check it
  if (recvfrom(connect_sock_d, buffer,MAX_BUFFER_SIZE, 0, (struct sockaddr*)&srv_addr,&sockaddr_len) == -1)
  {
    fprintf(stderr,"Function recvfrom() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }
  else if (strncmp(buffer,HELLO_ANS,strlen(HELLO_ANS)) != 0)
  {
    fprintf(stderr,"Server unsupport this protocol\n");
    goto finally;
  }
  memset(buffer,0,MAX_BUFFER_SIZE); // clear buffer
  strncpy(buffer,login,sizeof(buffer));
  // send login
  if (sendto(connect_sock_d, buffer,MAX_BUFFER_SIZE, 0, (struct sockaddr*)&srv_addr,sockaddr_len) == -1)
  {
    if (errno == ENOENT)
    {
      fprintf(stderr,"Server not working\n");
    }
    else fprintf(stderr,"Function sendto() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }
  memset(buffer,0,MAX_BUFFER_SIZE); // clear buffer
  ret = poll(fds, 1, TIMEOUT);
  if (ret <= 0)
  {
    fprintf(stderr,"Server is not responsing\n");
    goto finally;
  }
  // get response and check it
  if (recvfrom(connect_sock_d, buffer,MAX_BUFFER_SIZE, 0, (struct sockaddr*)&srv_addr,&sockaddr_len) == -1)
  {
    fprintf(stderr,"Function recvfrom() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }
  else if (strncmp(buffer,PASS_REQ,strlen(PASS_REQ)) != 0)
  {
    fprintf(stderr,"Server unsupport this protocol\n");
    goto finally;
  }
  memset(buffer,0,MAX_BUFFER_SIZE); // clear buffer
  strncpy(buffer,password,sizeof(buffer));
  // send password
  if (sendto(connect_sock_d, buffer,MAX_BUFFER_SIZE, 0, (struct sockaddr*)&srv_addr,sockaddr_len) == -1)
  {
    if (errno == ENOENT)
    {
      fprintf(stderr,"Server not working\n");
    }
    else fprintf(stderr,"Function sendto() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }
  memset(buffer,0,MAX_BUFFER_SIZE);
  ret = poll(fds, 1, TIMEOUT);
  if (ret <= 0)
  {
    fprintf(stderr,"Server is not responsing\n");
    goto finally;
  }
  // get response and check it
  if (recvfrom(connect_sock_d, buffer,MAX_BUFFER_SIZE, 0, (struct sockaddr*)&srv_addr,&sockaddr_len) == -1)
  {
    fprintf(stderr,"Function recvfrom() failed [Code:%d](%s)\n", errno, strerror(errno));
  }
  else if (strncmp(buffer,SUCCESS,strlen(SUCCESS)) == 0)
  {
    auth_res = true;
  }
  else if (strncmp(buffer,FAILED,strlen(FAILED)) == 0)
  {
    int_fast16_t buf_len = strlen(buffer);
    int_fast16_t fail_len = strlen(FAILED);
    if ((buf_len - fail_len) == 3) // space + first digit + second digit = 3
    {
      err_code = (buffer[buf_len-1]-'0')*10;
      err_code += (buffer[buf_len-2]-'0');
    }
    else if ((buf_len - fail_len) == 2) // space + one num = 2
    {
      err_code = (buffer[buf_len-1]-'0');		
    }
  }

finally:
  if (connect_sock_d != -1)
  {
    close(connect_sock_d);
  }
  unlink(temp_sock_name);
  
  return auth_res;
}

bool remoteChangePassword(char *srv_socket,char *login,char *password, char *new_password)
{
  bool change_res = false;
  if (login == NULL || strlen(login) == 0)
  {
    fprintf(stderr,"The user's login can't be empty\n");
    return change_res;
  }
  struct sockaddr_un srv_addr = {0};
  srv_addr.sun_family = AF_UNIX;
  memmove(srv_addr.sun_path, srv_socket,sizeof(srv_addr.sun_path));
  int_fast16_t connect_sock_d = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (connect_sock_d == -1)
  {
    fprintf(stderr,"Function socket() failed [Code:%d](%s)\n", errno, strerror(errno));
    return change_res;
  }
  struct sockaddr_un cli_addr = {0};
  cli_addr.sun_family = AF_UNIX;
  char temp_sock_name[sizeof(CLIENT_SOCKET_TEMPLATE)] = "";
  strncpy(temp_sock_name,CLIENT_SOCKET_TEMPLATE, sizeof(temp_sock_name));
  int_fast16_t sock_fd = 0;
  while ((sock_fd = mkstemp(temp_sock_name)) == -1 );
  close(sock_fd);
  memmove(cli_addr.sun_path, temp_sock_name, sizeof(cli_addr.sun_path));
  socklen_t sockaddr_len = sizeof(struct sockaddr_un);
  // Remove socket if it already exist
  if (unlink(temp_sock_name) == -1 && errno != ENOENT)
  {
    fprintf(stderr,"Function unlink() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }
  // Set nonblocking mode
  if (fcntl(connect_sock_d, F_SETFL, O_NONBLOCK) == -1)
  {
    fprintf(stderr,"Function fcntl() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }
  // Bind address settings to created socket
  if (bind(connect_sock_d,(struct sockaddr*)&cli_addr,sockaddr_len) == -1)
  {
    fprintf(stderr,"Function bind() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }

  char buffer[MAX_BUFFER_SIZE] = "";
  struct pollfd fds[1];
  fds[0].fd = connect_sock_d;
  fds[0].events = POLLIN;
  int_fast32_t ret = 0;
  strncpy(buffer,HELLO_CHPASSWD_MSG,sizeof(buffer));
  // send hello message which init protocol
  if (sendto(connect_sock_d, buffer,MAX_BUFFER_SIZE, 0, (struct sockaddr*)&srv_addr,sockaddr_len) == -1)
  {
    if (errno == ENOENT)
    {
      fprintf(stderr,"Server not working\n");
    }
    else fprintf(stderr,"Function sendto() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }
  memset(buffer,0,MAX_BUFFER_SIZE); // clear buffer
  ret = poll(fds, 1, TIMEOUT);
  if (ret <= 0)
  {
    fprintf(stderr,"Server is not responsing\n");
    goto finally;
  }
  // get response and check it
  if (recvfrom(connect_sock_d, buffer,MAX_BUFFER_SIZE, 0, (struct sockaddr*)&srv_addr,&sockaddr_len) == -1)
  {
    fprintf(stderr,"Function recvfrom() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }
  else if (strncmp(buffer,HELLO_ANS,strlen(HELLO_ANS)) != 0)
  {
    fprintf(stderr,"Server unsupport this protocol\n");
    goto finally;
  }
  memset(buffer,0,MAX_BUFFER_SIZE); // clear buffer
  strncpy(buffer,login,sizeof(buffer));
  // send login
  if (sendto(connect_sock_d, buffer,MAX_BUFFER_SIZE, 0, (struct sockaddr*)&srv_addr,sockaddr_len) == -1)
  {
    if (errno == ENOENT)
    {
      fprintf(stderr,"Server not working\n");
    }
    else fprintf(stderr,"Function sendto() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }
  memset(buffer,0,MAX_BUFFER_SIZE); // clear buffer
  ret = poll(fds, 1, TIMEOUT);
  if (ret <= 0)
  {
    fprintf(stderr,"Server is not responsing\n");
    goto finally;
  }
  // get response and check it
  if (recvfrom(connect_sock_d, buffer,MAX_BUFFER_SIZE, 0, (struct sockaddr*)&srv_addr,&sockaddr_len) == -1)
  {
    fprintf(stderr,"Function recvfrom() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }
  else if (strncmp(buffer,PASS_REQ,strlen(PASS_REQ)) != 0)
  {
    fprintf(stderr,"Server unsupport this protocol\n");
    goto finally;
  }
  memset(buffer,0,MAX_BUFFER_SIZE); // clear buffer
  strncpy(buffer,password,sizeof(buffer));
  // send password
  if (sendto(connect_sock_d, buffer,MAX_BUFFER_SIZE, 0, (struct sockaddr*)&srv_addr,sockaddr_len) == -1)
  {
    if (errno == ENOENT)
    {
      fprintf(stderr,"Server not working\n");
    }
    else fprintf(stderr,"Function sendto() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }
  memset(buffer,0,MAX_BUFFER_SIZE);
  ret = poll(fds, 1, TIMEOUT);
  if (ret <= 0)
  {
    fprintf(stderr,"Server is not responsing\n");
    goto finally;
  }
  if (recvfrom(connect_sock_d, buffer,MAX_BUFFER_SIZE, 0, (struct sockaddr*)&srv_addr,&sockaddr_len) == -1)
  {
    fprintf(stderr,"Function recvfrom() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }
  else if (strncmp(buffer,NEWPASS_REQ,strlen(buffer)) != 0)
  {
    fprintf(stderr,"Server unsupport this protocol\n");
    goto finally;
  }
  memset(buffer,0,MAX_BUFFER_SIZE); // clear buffer
  strncpy(buffer,new_password,sizeof(buffer));
  // send password
  if (sendto(connect_sock_d, buffer,MAX_BUFFER_SIZE, 0, (struct sockaddr*)&srv_addr,sockaddr_len) == -1)
  {
    if (errno == ENOENT)
    {
      fprintf(stderr,"Server not working\n");
    }
    else fprintf(stderr,"Function sendto() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }
  memset(buffer,0,MAX_BUFFER_SIZE); // clear buffer
  ret = poll(fds, 1, TIMEOUT);
  if (ret == 0 || ret == -1)
  {
    fprintf(stderr,"Server is not responsing\n");
    goto finally;
  }
  // get response and check it
  if (recvfrom(connect_sock_d, buffer,MAX_BUFFER_SIZE, 0, (struct sockaddr*)&srv_addr,&sockaddr_len) == -1)
  {
    fprintf(stderr,"Function recvfrom() failed [Code:%d](%s)\n", errno, strerror(errno));
    goto finally;
  }
  else if (strncmp(buffer,SUCCESS,strlen(SUCCESS)) == 0)
  {
    change_res = true;
  }
  else if (strncmp(buffer,FAILED,strlen(FAILED)) == 0)
  {
    int_fast16_t buf_len = strlen(buffer);
    int_fast16_t fail_len = strlen(FAILED);
    if ((buf_len - fail_len) == 3) // space + first digit + second digit = 3
    {
      err_code = (buffer[buf_len-1]-'0')*10;
      err_code += (buffer[buf_len-2]-'0');
    }
    else if ((buf_len - fail_len) == 2) // space + one num = 2
    {
      err_code = (buffer[buf_len-1]-'0');		
    }
  }

finally:
  if (connect_sock_d != -1)
  {
    close(connect_sock_d);
  }
  unlink(temp_sock_name);  

  return change_res;
}

int_fast8_t getErrorCode()
{
  return err_code;
}

const char *getErrorDescription(int_fast8_t err_code)
{
  memset(str_err,0,MAX_STRERROR_LEN);
  switch (err_code)
  {
    case AUTH_ERR:
      strncpy(str_err,AUTH_ERR_STR,MAX_STRERROR_LEN);
      break;
    case SERVER_PROBLEM:
      strncpy(str_err,SERVER_PROBLEM_STR,MAX_STRERROR_LEN);
      break;
    case UKNOWN_USER:
      strncpy(str_err,UKNOWN_USER_STR,MAX_STRERROR_LEN);
      break;
    case TOO_MANY_TRIES:
      strncpy(str_err,TOO_MANY_TRIES_STR,MAX_STRERROR_LEN);
      break;
    case EXPIRED_ACCOUNT:
      strncpy(str_err,EXPIRED_ACCOUNT_STR,MAX_STRERROR_LEN);
      break;
    case NEW_PASS_REQD:
      strncpy(str_err,NEW_PASS_REQD_STR,MAX_STRERROR_LEN);
      break;
    case PERM_DENIED:
      strncpy(str_err,PERM_DENIED_STR,MAX_STRERROR_LEN);
      break;
    case SHORT_PASSWORD:
      strncpy(str_err,SHORT_PASSWORD_STR,MAX_STRERROR_LEN);
      break;
    case SIMPLE_PASSWORD:
      strncpy(str_err,SIMPLE_PASSWORD_STR,MAX_STRERROR_LEN);
      break;
    case SYSTEMATIC_PASSWORD:
      strncpy(str_err,SYSTEMATIC_PASSWORD_STR,MAX_STRERROR_LEN);
      break;
    case NOT_ENOUGH_DIFF_PASSWORD:
      strncpy(str_err,NOT_ENOUGH_DIFF_PASSWORD_STR,MAX_STRERROR_LEN);
      break;
    case NOT_YET_TIME:
      strncpy(str_err,NOT_YET_TIME_STR,MAX_STRERROR_LEN);
      break;
    case UKNOWN_ERROR:
      strncpy(str_err,UKNOWN_ERROR_STR,MAX_STRERROR_LEN);
      break;
    default:
      strncpy(str_err,UKNOWN_ERROR_STR,MAX_STRERROR_LEN);
      break;
  }
  return str_err;
}
