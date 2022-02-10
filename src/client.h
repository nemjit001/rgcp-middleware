#ifndef RGCP_MIDDLEWARE_CLIENT
#define RGCP_MIDDLEWARE_CLIENT

#include <arpa/inet.h>
#include <sys/socket.h>

#include "details/rgcp_group.h"
#include "details/linked_list.h"

struct client
{
    // packet ptr?? || queue?? for comms with main process
    
    struct list_entry m_listEntry;
    pthread_t m_threadHandle;
    int m_shutdownFlag;
    int m_remoteFd;

    struct
    {
        struct sockaddr_in m_peerAddress;
        socklen_t m_addrLen;
    } m_connectionInfo;

    struct client* m_pSelf;
};

void client_init(struct client* pClient, struct sockaddr_in peerAddress, int remoteFd);

void client_free(struct client client);

void *client_thread_main(void *pClient);

#endif 