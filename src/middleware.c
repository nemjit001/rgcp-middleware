#include "middleware.h"

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "details/logger.h"

static struct middleware_state g_middlewareState = { 0 };

static void handle_signal(int signum)
{
    if (signum == SIGINT)
    {
        g_middlewareState.m_shutdownFlag = 1;
    }
}

void _register_thread_signals()
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
}

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
    memset(pState, 0, sizeof(*pState));

    list_init(&(pState->m_childListHead));
    list_init(&(pState->m_groupListHead));

    pState->m_numClients = 0;
    pState->m_numGroups = 0;

    pState->m_listenSocket = -1;
    pState->m_listenSocket = _create_listen_socket(8000);

    if (pState->m_listenSocket < 0)
        return -1;

    pState->m_shutdownFlag = 0;
    pState->m_pollingInfo.m_pollFds = NULL;
    pState->m_pollingInfo.m_pollFdSize = 0;

    return 0;
}

void middleware_state_free(struct middleware_state* pState)
{
    close(pState->m_listenSocket);

    struct list_entry* pCurr, * pNext;
    LIST_FOR_EACH(pCurr, pNext, &(pState->m_childListHead))
    {
        struct client* pClient = LIST_ENTRY(pCurr, struct client, m_listEntry);
        pClient->m_shutdownFlag = 1;

        pthread_join(pClient->m_threadHandle, NULL);
        client_free((*pClient));
        free(pClient);
    }

    if (pState->m_pollingInfo.m_pollFds != NULL)
        free(pState->m_pollingInfo.m_pollFds);
}

int middleware_handle_incoming(struct middleware_state* pState)
{
    int successFlag = 1;
    
    nfds_t numSockets = pState->m_numClients + 1;

    if (numSockets != pState->m_pollingInfo.m_pollFdSize || pState->m_pollingInfo.m_pollFds == NULL)
    {
        log_msg(LOG_LEVEL_DEBUG, "[Middleware] Changing Polling FD Count\n");

        if (pState->m_pollingInfo.m_pollFds != NULL)
            free(pState->m_pollingInfo.m_pollFds);

        pState->m_pollingInfo.m_pollFds = calloc(numSockets, sizeof(struct pollfd));
        pState->m_pollingInfo.m_pollFdSize = numSockets;
    }
    else
    {
        memset(pState->m_pollingInfo.m_pollFds, 0, pState->m_pollingInfo.m_pollFdSize * sizeof(struct pollfd));
    }

    struct pollfd listenFd;

    listenFd.fd = pState->m_listenSocket;
    listenFd.events = POLLIN;
    listenFd.revents = 0;
    
    pState->m_pollingInfo.m_pollFds[0] = listenFd;
    int idx = 1;
    struct list_entry *pCurr, *pNext;
    LIST_FOR_EACH(pCurr, pNext, &pState->m_childListHead)
    {
        struct client* pClient = LIST_ENTRY(pCurr, struct client, m_listEntry);
        struct pollfd* pCurrPollFd = &(pState->m_pollingInfo.m_pollFds[idx]);

        pCurrPollFd->fd = pClient->m_communicationSockets.m_clientThreadSocket;
        pCurrPollFd->events = POLLIN;
        pCurrPollFd->revents = 0;

        idx++;
    }

    if (poll(pState->m_pollingInfo.m_pollFds, pState->m_pollingInfo.m_pollFdSize, 0) < 0)
    {
        if (errno == EINTR)
            return 0;

        perror("Middleware failed to poll ready sockets");
        return -1;
    }

    if (pState->m_pollingInfo.m_pollFds[0].revents & POLLIN)
    {
        if (middleware_handle_new_connection(pState) < 0)
            successFlag = 0;
    }

    idx = 1;
    LIST_FOR_EACH(pCurr, pNext, &pState->m_childListHead)
    {
        struct client* pClient = LIST_ENTRY(pCurr, struct client, m_listEntry);
        struct pollfd* pCurrPollFd = &(pState->m_pollingInfo.m_pollFds[idx]);
        
        if (pCurrPollFd->revents & POLLIN)
        {
            log_msg(LOG_LEVEL_DEBUG, "[Middleware] Client [%p] has data for middleware\n", (void*)pClient);
            if (middleware_handle_client_message(pState, pClient) < 0)
            {
                successFlag = 0;
                break;
            }
        }

        idx++;
    }

    return successFlag;
}

int middleware_handle_client_message(__attribute__((unused)) struct middleware_state* pState, __attribute__((unused)) struct client *pClient)
{
    // FIXME: implement
    return -1;
}

int middleware_check_client_states(struct middleware_state* pState)
{
    struct list_entry* pCurr, * pNext;
    LIST_FOR_EACH(pCurr, pNext, &(pState->m_childListHead))
    {
        struct client* pClient = LIST_ENTRY(pCurr, struct client, m_listEntry);
       
        if (pClient->m_shutdownFlag == 1)
        {
            if (pthread_join(pClient->m_threadHandle, NULL) < 0)
            {
                if (errno == EINTR)
                    continue;

                return -1;
            }

            list_del(pCurr);
            client_free((*pClient));
            free(pClient);

            pState->m_numClients--;
        }
    }

    return 0;
}

int middleware_check_group_states(struct middleware_state* pState)
{
    struct list_entry* pCurr, * pNext;
    LIST_FOR_EACH(pCurr, pNext, &(pState->m_childListHead))
    {
        struct rgcp_group* pGroup = LIST_ENTRY(pCurr, struct rgcp_group, m_listEntry);
       
        if (rgcp_group_empty(*pGroup))
        {
            log_msg(LOG_LEVEL_INFO, "[Middleware] Deleted group \"%s\"(%u)\n", pGroup->m_groupNameInfo.m_pGroupName, pGroup->m_groupNameInfo.m_groupHash);

            rgcp_group_free(*pGroup);
            list_del(pCurr);

            pState->m_numGroups--;
        }
    }

    return 0;
}

int middleware_handle_new_connection(struct middleware_state* pState)
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
    
    if (client_init(pNewClient, peerAddr, connectionFd) < 0)
    {
        free(pNewClient);
        return -1;
    }

    if (pthread_create(&pNewClient->m_threadHandle, NULL, client_thread_main, (void*)pNewClient) < 0)
    {
        client_free(*pNewClient);
        free(pNewClient);
        return -1;
    }

    list_add_tail(&pNewClient->m_listEntry, &pState->m_childListHead);
    pState->m_numClients++;
    log_msg(LOG_LEVEL_INFO, "[Middleware] New Client Connected!\n");

    return 0;
}

int middleware_handle_new_group(__attribute__((unused)) struct middleware_state* pState, __attribute__((unused)) const char* pGroupName)
{
    // FIXME: implement
    return -1;
}

int main(__attribute__((unused)) int argc, __attribute__((unused)) char** argv)
{
    logger_init();
    if (middleware_state_init(&g_middlewareState) < 0)
    {
        perror("Failed to initialize Middleware");
        return -1;
    }

    log_msg(LOG_LEVEL_INFO, "[Middleware] Initialized Middleware...\n");
    _register_thread_signals();

    while(g_middlewareState.m_shutdownFlag == 0)
    {
        if (middleware_handle_incoming(&g_middlewareState) == 0)
            break;

        if (middleware_check_client_states(&g_middlewareState) < 0)
            break;
    } 

    log_msg(LOG_LEVEL_INFO, "[Middleware] Shutting Down Middleware...\n");
    middleware_state_free(&g_middlewareState);
    logger_free();

    return 0;
}