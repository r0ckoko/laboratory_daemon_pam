#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "protocol.h"

int_fast8_t err_code = 0;

int dialog(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *app_data)
{
  if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG)
  {
    return PAM_CONV_ERR;
  }

  struct pam_response *buf = (struct pam_response*)calloc(num_msg, sizeof(struct pam_response));

  if (buf == NULL)
  {
    return PAM_BUF_ERR;
  }

  for (int i = 0; i < num_msg; ++i)
  {
    if (err_code)
    {
      return PAM_CONV_ERR;
    }
    if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF)
    {
      if (strncmp(msg[i]->msg, "Пароль: ", strlen(msg[i]->msg)) == 0 )
      {
        buf[i].resp_retcode = 0;
        buf[i].resp = (char*)app_data;
      }
      else if (strncmp(msg[i]->msg, "Введите текущий пароль: ", strlen(msg[i]->msg)) == 0)
      {
        buf[i].resp_retcode = 0;
        char *char_app_data = (char*)app_data;
        char *current_password = (char*)calloc(strlen(char_app_data)+1, sizeof(char));
        strncpy(current_password, char_app_data, strlen(char_app_data));
        buf[i].resp = current_password;
      }
      else if ((strncmp(msg[i]->msg,"Новый UNIX пароль: ",strlen(msg[i]->msg)) == 0) ||
              (strncmp(msg[i]->msg,"Введите новый пароль: ",strlen(msg[i]->msg))==0))
      {
        buf[i].resp_retcode = 0;
        char *char_app_data = (char*)app_data;
        char *temp = (char_app_data+strlen(char_app_data)+2);
        char *new_password = (char*)calloc(strlen(temp), sizeof(char));
        strncpy(new_password, temp, strlen(temp));
        buf[i].resp = new_password;
      }
      else if ((strncmp(msg[i]->msg,"Наберите новый UNIX пароль еще раз: ",strlen(msg[i]->msg)) == 0) ||
              (strncmp(msg[i]->msg,"Наберите новый пароль еще раз: ",strlen(msg[i]->msg))==0))
      {
        buf[i].resp_retcode = 0;
        char *char_app_data = (char*)app_data;
        char *temp = (char_app_data+strlen(char_app_data)+2);
        char *new_password = (char*)calloc(strlen(temp), sizeof(char));
        strncpy(new_password, temp, strlen(temp));
        buf[i].resp = new_password;
      }
      else
      {
	      buf[i].resp_retcode = 0;
	      buf[i].resp = NULL;
      }
    }
    else if (msg[i]->msg_style == PAM_ERROR_MSG)
    {
      if ((strncmp(msg[i]->msg,"Неверный пароль: it is too short",strlen(msg[i]->msg)) == 0) ||
          (strncmp(msg[i]->msg,"Неверный пароль: it is WAY too short",strlen(msg[i]->msg)) == 0))
      {
        err_code = SHORT_PASSWORD;
      }
      else if (strncmp(msg[i]->msg,"Неверный пароль: is too simple",strlen(msg[i]->msg)) == 0)
      {
        err_code = SIMPLE_PASSWORD;
      }
      else if (strncmp(msg[i]->msg,"Неверный пароль: it is too simplistic/systematic",strlen(msg[i]->msg)) == 0)
      {
        err_code = SYSTEMATIC_PASSWORD;
      }
      else if (strncmp(msg[i]->msg,"Неверный пароль: it does not contain enough DIFFERENT characters",strlen(msg[i]->msg)) == 0)
      {
        err_code = NOT_ENOUGH_DIFF_PASSWORD;
      }
      else if (strncmp(msg[i]->msg,"You must wait longer to change your password",strlen(msg[i]->msg)) == 0)
      {
        err_code = NOT_YET_TIME;
      }
      else
      {
	      err_code = UKNOWN_ERROR;
      }
      return PAM_CONV_ERR;
    }
  }
  *resp = buf;

  return PAM_SUCCESS;
}

int_fast8_t auth(char* login, char *password)
{
  struct pam_conv pam_conversation;
  memset(&pam_conversation,0,sizeof(struct pam_conv));
  pam_conversation.conv = dialog;
  pam_conversation.appdata_ptr = strndup(password,strlen(password));
  pam_handle_t *pam_handle = NULL;
  int_fast8_t ret = 0;
  ret = pam_start(PAM_SERVICE_NAME, login, &pam_conversation, &pam_handle);
  if (ret != PAM_SUCCESS)
  {
    return SERVER_PROBLEM;
  }
  ret = pam_authenticate(pam_handle, 0);
  if (ret != PAM_SUCCESS)
  {
    switch (ret)
    {
      case PAM_AUTH_ERR:
        ret = AUTH_ERR;
        break;
      case PAM_USER_UNKNOWN:
        ret = UKNOWN_USER;
        break;
      case PAM_MAXTRIES:
        ret = TOO_MANY_TRIES;
        break;
      default:
        ret = UKNOWN_ERROR;
        break;
    }
    pam_end(pam_handle, 0);
    return ret;
  }
  ret = pam_acct_mgmt(pam_handle,0);
  if (ret != PAM_SUCCESS)
  {
    switch (ret)
    {
      case PAM_ACCT_EXPIRED:
        ret = EXPIRED_ACCOUNT;
        break;
      case PAM_NEW_AUTHTOK_REQD:
        ret = NEW_PASS_REQD;
        break;
      default:
        ret = UKNOWN_ERROR;
        break;
    }
    pam_end(pam_handle, 0);
    return ret;
  }
  pam_end(pam_handle, 0);

  return ret;
}

int_fast8_t changePassword(char *login, char *current_password, char *new_password)
{
  struct pam_conv pam_conversation;
  memset(&pam_conversation,0,sizeof(struct pam_conv));
  pam_conversation.conv = dialog;
  int_fast16_t sum_len = strlen(current_password)+strlen(new_password)+2;
  char *two_pass_in_one_str = (char*)calloc(sum_len, sizeof(char));
  strncpy(two_pass_in_one_str,current_password,strlen(current_password));
  strncpy(two_pass_in_one_str+strlen(current_password)+2,new_password, strlen(new_password));

  pam_conversation.appdata_ptr = two_pass_in_one_str;
  pam_handle_t *pam_handle = NULL;
  int_fast8_t ret = 0;
  ret = pam_start(PAM_SERVICE_NAME, login, &pam_conversation, &pam_handle);
  if (ret != PAM_SUCCESS)
  {
    return SERVER_PROBLEM;
  }
  ret = pam_chauthtok(pam_handle, 0);
  if (ret != PAM_SUCCESS && err_code == 0)
  {
    switch (ret)
    {
      case PAM_PERM_DENIED:
        ret = PERM_DENIED;
        break;
      case PAM_USER_UNKNOWN:
        ret = UKNOWN_USER;
        break;
      default:
        ret = UKNOWN_ERROR;
        break;
    }
    pam_end(pam_handle, 0);
    return ret;
  }
  else
  {
    ret = err_code;
    err_code = 0;
  }
  pam_end(pam_handle, 0);
  return ret;
}