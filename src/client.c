#include "client.h"

#include <assert.h>
#include <unistd.h>
#include <poll.h>
#include <stdio.h>
#include <errno.h>

#include "details/logger.h"

int client_init(struct client* pClient, struct sockaddr_in peerAddress, int remoteFd)
{
    assert(pClient);
    pClient->m_threadHandle = 0;
    pClient->m_shutdownFlag = 0;
    pClient->m_remoteFd = remoteFd;
    pClient->m_connectionInfo.m_peerAddress = peerAddress;
    pClient->m_connectionInfo.m_addrLen = sizeof(peerAddress);

    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0)
        return -1;

    pClient->m_communicationSockets.m_mainThreadSocket = sockets[0];
    pClient->m_communicationSockets.m_clientThreadSocket = sockets[1];

    pClient->m_pSelf = pClient;
    return 0;
}

void client_free(struct client client)
{
    close(client.m_communicationSockets.m_mainThreadSocket);
    close(client.m_communicationSockets.m_clientThreadSocket);
    close(client.m_remoteFd);
}

int client_handle_remote_request(__attribute__((unused)) struct client* pClient)
{
    //

    return -1;
}

int client_handle_incoming(struct client* pClient)
{
    int successFlag = 1;
    
    struct pollfd remote;
    remote.fd = pClient->m_remoteFd;
    remote.events = POLLIN;
    remote.revents = 0;

    if (poll(&remote, 1, 0) < 0)
    {
        if (errno != EINTR)
        {
            perror("Client Thread FD Poll failed");
            successFlag = 0;
        }
    }

    if (remote.revents & POLLHUP)
    {
        // remote closed
        log_msg(LOG_LEVEL_INFO, "[Client][%d] Remote Closed\n", pClient->m_remoteFd);
        pClient->m_shutdownFlag = 1;
        return successFlag;
    }
    else if (remote.revents & POLLIN)
    {
        log_msg(LOG_LEVEL_DEBUG, "[Client][%d] Remote Has Data Available\n", pClient->m_remoteFd);
        // read data from client
    }
    else if (remote.revents & POLLNVAL)
    {
        perror("Client FD Poll Returned Invalid");
        successFlag = 0;
    }

    return successFlag;
}

void *client_thread_main(void *pClientInfo)
{
    assert(pClientInfo);

    struct client* pClient = (struct client*)(pClientInfo);
    assert(pClient->m_pSelf == pClient);

    if (pClient->m_pSelf != pClient)
    {
        perror("Invalid Pointer passed to client thread...");
        pthread_exit(NULL);
    }

    log_msg(LOG_LEVEL_INFO, "[Client][%d] Initialized Client Thread...\n", pClient->m_remoteFd);

    while(pClient->m_shutdownFlag == 0)
    {
        if (client_handle_incoming(pClient) == 0)
        {
            perror("Client failed to handle message, shutting down thread...");
            pClient->m_shutdownFlag = 1;
        }
    }

    log_msg(LOG_LEVEL_INFO, "[Client][%d] Shut Down Client Thread...\n", pClient->m_remoteFd);

    return NULL;
}