#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <security/pam_appl.h>
#include <stdint.h>
#include <stdbool.h>

#define AUTH_REQ 1
#define HELLO_AUTH_MSG "KNOCK KNOCK"
#define HELLO_ANS "WHO IS THERE?"
#define PASS_REQ "PASSWORD?"
#define SUCCESS "COME IN"
#define FAILED "GO AWAY"
#define CHPASSWD_REQ 2
#define HELLO_CHPASSWD_MSG "KNOCK KNOCK KNOCK"
#define NEWPASS_REQ "NEW PASSWORD?"
#define STAND_IN_LINE "STAND IN LINE"

#define NULL_STEP 0
#define FIRST_STEP 1
#define SECOND_STEP 2
#define THIRD_STEP 3

#define PAM_SERVICE_NAME "knock-knock"
#define CLIENT_SOCKET_TEMPLATE "/tmp/knocker-XXXXXX"
#define MAX_BUFFER_SIZE 1024
#define DEFAULT_INPUT_MESSAGE "Password"
#define TIMEOUT 5000 // in milliseconds
#define MAX_STRERROR_LEN 255

enum ERR_CODES
{
  AUTH_ERR = 1,
  SERVER_PROBLEM = 2,
  UKNOWN_USER = 3,
  TOO_MANY_TRIES = 4,
  EXPIRED_ACCOUNT = 5,
  NEW_PASS_REQD = 6,
  PERM_DENIED = 7,
  SHORT_PASSWORD = 8,
  SIMPLE_PASSWORD = 9,
  SYSTEMATIC_PASSWORD = 10,
  NOT_ENOUGH_DIFF_PASSWORD = 11,
  NOT_YET_TIME = 12,
  UKNOWN_ERROR = 13
};
#define AUTH_ERR_STR "Wrong password"
#define SERVER_PROBLEM_STR "Server has a problem with authentication modules"
#define UKNOWN_USER_STR "There is no user with this login"
#define TOO_MANY_TRIES_STR "Number of authentication attempts exhausted"
#define EXPIRED_ACCOUNT_STR "Account expired"
#define NEW_PASS_REQD_STR "Current password expired. A new password is required"
#define PERM_DENIED_STR "Permission denied for operation"
#define SHORT_PASSWORD_STR "Password is short"
#define SIMPLE_PASSWORD_STR "Password is simple"
#define SYSTEMATIC_PASSWORD_STR "Password is systematic/simplestic"
#define NOT_ENOUGH_DIFF_PASSWORD_STR "Password consist of not enough different symbols"
#define NOT_YET_TIME_STR "Not enough time has passed since last password change"
#define UKNOWN_ERROR_STR "Uknown error"

extern int_fast8_t err_code;
extern char str_err[MAX_STRERROR_LEN];

static int dialog(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *app_data);
int_fast8_t auth(char *login, char *password);
int_fast8_t changePassword(char *login, char *current_password, char *new_password);
bool remoteChangePassword(char *srv_socket,char *login, char *current_password, char *new_password);
bool remoteAuth(char *srv_socket, char *login, char *password);
int_fast32_t secureInput(char *password, int_fast16_t size,char *input_msg);
int_fast8_t getErrorCode();
const char* getErrorDescription(int_fast8_t err_code);

#endif // PROTOCOL_H
