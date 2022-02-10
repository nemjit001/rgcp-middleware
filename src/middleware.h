#ifndef RGCP_MIDDLEWARE
#define RGCP_MIDDLEWARE

#include "details/linked_list.h"

struct middleware_state
{
    struct list_entry m_groupListHead;
    struct list_entry m_childListHead;
    int m_listenSocket;
};

int middleware_state_init(struct middleware_state* pState);

void middleware_state_free(struct middleware_state state);

int handle_incoming(struct middleware_state* pState);

int handle_new_connection(struct middleware_state* pState);

#endif