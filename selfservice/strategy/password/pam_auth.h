#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int conversation(int num_msg, const struct pam_message **msg,
                 struct pam_response **resp, void *appdata_ptr) {
    if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG) {
        return PAM_CONV_ERR;
    }

    *resp = calloc(num_msg, sizeof(struct pam_response));
    if (*resp == NULL) {
        return PAM_BUF_ERR;
    }

    for (int i = 0; i < num_msg; i++) {
        switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
                (*resp)[i].resp = strdup((char *)appdata_ptr);
                break;
            case PAM_PROMPT_ECHO_ON:
                (*resp)[i].resp = strdup((char *)appdata_ptr);
                break;
            case PAM_ERROR_MSG:
            case PAM_TEXT_INFO:
                break;
            default:
                free(*resp);
                return PAM_CONV_ERR;
        }
    }

    return PAM_SUCCESS;
}

int authenticate(const char *service, const char *username, const char *password) {
    pam_handle_t *pamh = NULL;
    int pam_error;
    struct pam_conv conv = {
        conversation,
        (void *)password
    };

    pam_error = pam_start(service, username, &conv, &pamh);
    if (pam_error != PAM_SUCCESS) {
        return 0;
    }

    pam_error = pam_authenticate(pamh, 0);
    if (pam_error != PAM_SUCCESS) {
        pam_end(pamh, pam_error);
        return 0;
    }

    pam_end(pamh, PAM_SUCCESS);
    return 1;
}

