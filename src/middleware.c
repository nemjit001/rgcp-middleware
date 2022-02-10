#include "middleware.h"

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "client.h"

int _create_listen_socket(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in address;

    memset(&address, 0, sizeof(address));
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_family = AF_INET;
    address.sin_port = htons(port);

    if (fd < 0)
        return -1;

    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        close(fd);
        return -1;
    }

    if (listen(fd, SOMAXCONN) < 0)
    {
        close(fd);
        return -1;
    }

    return fd;
}

int middleware_state_init(struct middleware_state* pState)
{
    list_init(&pState->m_childListHead);
    list_init(&pState->m_groupListHead);
    pState->m_listenSocket = -1;
    pState->m_listenSocket = _create_listen_socket(8000);

    if (pState->m_listenSocket < 0)
        return -1;

    return 0;
}

void middleware_state_free(struct middleware_state state)
{
    close(state.m_listenSocket);

    struct list_entry* pCurr = NULL, * pNext = NULL;

    LIST_FOR_EACH(pCurr, pNext, (&state.m_childListHead))
    {
        struct client* pClient = LIST_ENTRY(pCurr, struct client, m_listEntry);
        pClient->m_shutdownFlag = 1;
        
        pthread_join(pClient->m_threadHandle, NULL);
    }
}

int handle_incoming(__attribute__((unused)) struct middleware_state* pState)
{
    int successFlag = 1;
    int maxFd = pState->m_listenSocket;
    fd_set readFds;
    FD_ZERO(&readFds);

    FD_SET(pState->m_listenSocket, &readFds);

    if (select(maxFd + 1, &readFds, NULL, NULL, NULL) < 0)
    {
        if (errno == EINTR)
            return 0;

        perror("Middleware failed to select ready sockets");
        return -1;
    }

    if (FD_ISSET(pState->m_listenSocket, &readFds))
    {
        if (handle_new_connection(pState) < 0)
            successFlag = 0;
    }

    return successFlag;
}

int handle_new_connection(struct middleware_state* pState)
{
    struct sockaddr_in peerAddr;
    socklen_t peerAddrLen = sizeof(peerAddr);

    int connectionFd = accept(pState->m_listenSocket, (struct sockaddr *)&peerAddr, &peerAddrLen);

    if (connectionFd < 0)
    {
        if (errno == EINTR)
            return 0;
        
        perror("Middleware failed to accept a new connection");
        return -1;
    }

    struct client* pNewClient = calloc(sizeof(struct client), 1);
    client_init(pNewClient, peerAddr, connectionFd);
    list_add_tail(&pNewClient->m_listEntry, &pState->m_childListHead);

    pthread_create(&pNewClient->m_threadHandle, NULL, client_thread_main, (void*)pNewClient);

    return 0;
}

int main(__attribute__((unused)) int argc, __attribute__((unused)) char** argv)
{
    struct middleware_state state;

    if (middleware_state_init(&state) < 0)
    {
        perror("Failed to init Middleware");
        return -1;
    }

    for (;;)
    {
        if (!handle_incoming(&state))
            break;
    } 

    middleware_state_free(state);

    return 0;
}