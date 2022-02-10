#include "client.h"

#include <assert.h>
#include <unistd.h>

void client_init(struct client* pClient, struct sockaddr_in peerAddress, int remoteFd)
{
    assert(pClient);
    pClient->m_threadHandle = 0;
    pClient->m_shutdownFlag = 0;
    pClient->m_remoteFd = remoteFd;
    pClient->m_connectionInfo.m_peerAddress = peerAddress;
    pClient->m_connectionInfo.m_addrLen = sizeof(peerAddress);

    pClient->m_pSelf = pClient;
}

void client_free(struct client client)
{
    close(client.m_remoteFd);
}

void *client_thread_main(void *pClientInfo)
{
    assert(pClientInfo);

    struct client* pClient = (struct client*)(pClientInfo);
    assert(pClient->m_pSelf == pClient);

    while(pClient->m_shutdownFlag == 0)
    {
        // listen for packets of remote
    }

    return NULL;
}