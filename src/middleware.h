#ifndef RGCP_MIDDLEWARE
#define RGCP_MIDDLEWARE

#include <poll.h>

#include "client.h"
#include "details/linked_list.h"

struct middleware_state
{
    struct list_entry m_groupListHead;
    struct list_entry m_childListHead;

    size_t m_numGroups;
    size_t m_numClients;

    int m_listenSocket;
    int m_shutdownFlag;

    struct 
    {
        struct pollfd* m_pollFds;
        size_t m_pollFdSize;
    } m_pollingInfo;
};

int middleware_state_init(struct middleware_state* pState);

void middleware_state_free(struct middleware_state* pState);

int middleware_handle_incoming(struct middleware_state* pState);

int middleware_handle_client_message(struct middleware_state* pState, struct client *pClient);

int middleware_check_client_states(struct middleware_state* pState);

int middleware_check_group_states(struct middleware_state* pState);

int middleware_handle_new_connection(struct middleware_state* pState);

int middleware_handle_new_group(struct middleware_state* pState, const char* pGroupName);

#endif