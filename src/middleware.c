#include "middleware.h"

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <rgcp/rgcp_group.h>

#include "details/logger.h"

#define MIDDLEWARE_DEFAULT_PORT 8000
#define MIDDLEWARE_DEFAULT_HEARTBEAT_TIMEOUT_SECONDS 30

static struct middleware_state g_middlewareState = { 0 };

static void handle_signal(int signum)
{
    if (signum & SIGINT)
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

int _send_middleware_groups(struct middleware_state* pState, __attribute__((unused)) struct client* pClient)
{
    struct rgcp_middleware_group** ppGroups = NULL;
    size_t groupCount = middleware_get_groups(pState, &ppGroups);
    
    uint8_t* pGroupInfoBuffer = NULL;
    ssize_t totalBufferSize = 0;
    for (size_t i = 0; i < groupCount; i++)
    {
        uint8_t* pTempBuffer = NULL;
        ssize_t ptrSize = serialize_group_name_info((ppGroups[i]->m_groupNameInfo), &pTempBuffer);

        if (ptrSize < 0)
        {
            free(pGroupInfoBuffer);
            free(pTempBuffer);
            return -1;
        }

        ssize_t oldBufferSize = totalBufferSize;
        totalBufferSize += ptrSize + sizeof(uint32_t);
        pGroupInfoBuffer = realloc(pGroupInfoBuffer, totalBufferSize);

        assert(totalBufferSize > oldBufferSize);
        assert(pTempBuffer);
        assert(pGroupInfoBuffer);

        memset(pGroupInfoBuffer + oldBufferSize, 0, sizeof(uint32_t) + ptrSize);
        memcpy(pGroupInfoBuffer + oldBufferSize, ((uint32_t*)&ptrSize), sizeof(uint32_t));
        memcpy(pGroupInfoBuffer + oldBufferSize + sizeof(uint32_t), pTempBuffer, ptrSize);

        free(pTempBuffer);
    }

    if (pGroupInfoBuffer == NULL)
        assert(totalBufferSize == 0);

    log_msg(LOG_LEVEL_DEBUG, "[Middleware] Collected %d group(s) @ %p (%ld bytes)\n", groupCount, pGroupInfoBuffer, totalBufferSize);

    if (middleware_forward_packet_data(pClient, API_GROUP_DISCOVERY, pGroupInfoBuffer, totalBufferSize) < 0)
    {
        free(ppGroups);
        free(pGroupInfoBuffer);
        return -1;
    }

    free(ppGroups);
    free(pGroupInfoBuffer);
    return 0;
}

int middleware_state_init(struct middleware_state* pState, uint16_t port, time_t heartbeatTimeoutSeconds)
{
    memset(pState, 0, sizeof(*pState));

    list_init(&(pState->m_childListHead));
    list_init(&(pState->m_groupListHead));

    pState->m_numClients = 0;
    pState->m_numGroups = 0;

    pState->m_listenSocket = -1;
    pState->m_listenSocket = _create_listen_socket(port);

    pState->m_heartbeatTimeout = heartbeatTimeoutSeconds;

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

    LIST_FOR_EACH(pCurr, pNext, &(pState->m_groupListHead))
    {
        struct rgcp_middleware_group* pGroup = LIST_ENTRY(pCurr, struct rgcp_middleware_group, m_listEntry);
        rgcp_middleware_group_free(*pGroup);
        free(pGroup);
    }

    if (pState->m_pollingInfo.m_pollFds != NULL)
        free(pState->m_pollingInfo.m_pollFds);
}

int middleware_forward_packet_data(struct client* pClient, enum API_PACKET_TYPE packetType, uint8_t* pPacketData, size_t dataLength)
{
    assert(pClient);

    if (pPacketData == NULL)
        dataLength = 0;

    struct api_packet* pPacket = NULL;
    if (api_packet_init(&pPacket, dataLength) < 0)
        return -1;
    
    if (pPacketData != NULL)
        memcpy(pPacket->m_packetData, pPacketData, dataLength);
    
    pPacket->m_packetType = packetType;
    pPacket->m_dataLen = dataLength;

    if (api_packet_send(pClient->m_communicationSockets.m_clientThreadSocket, pPacket) < 0)
    {
        api_packet_free(pPacket);
        return -1;
    }

    api_packet_free(pPacket);
    return dataLength;
}

int middleware_handle_incoming(struct middleware_state* pState)
{
    int successFlag = 1;
    nfds_t numSockets = pState->m_numClients + 1;

    if (numSockets != pState->m_pollingInfo.m_pollFdSize || pState->m_pollingInfo.m_pollFds == NULL)
    {
        log_msg(LOG_LEVEL_DEBUG, "[Middleware] Changing Polling FD Count to %d\n", numSockets);

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

    pCurr = NULL;
    pNext = NULL;
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

    // client count can change, so new connections need to be managed after handling all client messages
    if (pState->m_pollingInfo.m_pollFds[0].revents & POLLIN)
    {
        if (middleware_handle_new_connection(pState) < 0)
            successFlag = 0;
    }

    return successFlag;
}

int middleware_handle_client_message(struct middleware_state* pState, struct client *pClient)
{
    struct api_packet* pPacket = NULL;
    if (api_packet_recv(pClient->m_communicationSockets.m_clientThreadSocket, &pPacket) < 0)
    {
        log_msg(LOG_LEVEL_ERROR, "[Middleware] Receive from Client [%p] has failed\n", (void*)pClient);
        return -1;
    }

    log_msg(LOG_LEVEL_DEBUG, "[Middleware] Received packet from Client [%p]: (%d, %d, %lu)\n", (void*)pClient, pPacket->m_packetType, pPacket->m_errorType, pPacket->m_dataLen);

    // FIXME: finish implementation
    switch (pPacket->m_packetType)
    {
    case API_DISCONNECT:
    {
        if (middleware_forward_packet_data(pClient, API_DISCONNECT, NULL, 0) < 0)
            goto error;

        break;
    }
    case API_GROUP_CREATE:
    {
        char* groupname = calloc(pPacket->m_dataLen, sizeof(char));
        assert(groupname);
        memcpy(groupname, pPacket->m_packetData, pPacket->m_dataLen);

        if (middleware_handle_new_group(pState, groupname) < 0)
        {
            free(groupname);
            goto error;
        }

        free(groupname);
        if (middleware_forward_packet_data(pClient, API_GROUP_CREATE, NULL, 0) < 0)
            goto error;
        
        break;
    }
    case API_GROUP_DISCOVERY:
    {
        if(_send_middleware_groups(pState, pClient) < 0)
            goto error;

        break;
    }
    case API_GROUP_JOIN:
    {
        // TODO: register client with group, send response to remote
        break;
    }
    case API_GROUP_LEAVE:
    {
        // TODO: remove client from group, send response to remote
        break;
    }
    default:
        log_msg(LOG_LEVEL_ERROR, "[Middleware] Invalid packet type from Client [%p]\n", (void*)pClient);
        return -1;
    }

    api_packet_free(pPacket);
    return 0;

error:
    api_packet_free(pPacket);
    return -1;
}

int middleware_check_client_states(struct middleware_state* pState)
{
    struct list_entry* pCurr, * pNext;
    LIST_FOR_EACH(pCurr, pNext, &(pState->m_childListHead))
    {
        struct client* pClient = LIST_ENTRY(pCurr, struct client, m_listEntry);
        time_t currentTime = time(NULL);
        time_t delta = currentTime - pClient->m_lastHeartbeatTimestamp;
       
        if (pClient->m_shutdownFlag == 1 || delta > (2 * pState->m_heartbeatTimeout))
        {
            if (delta > (2 * pState->m_heartbeatTimeout))
                log_msg(LOG_LEVEL_ERROR, "[Middleware] Client[%d] shut down, heartbeat message not received for 2 periods...\n", pClient->m_remoteFd);

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

int middleware_handle_new_group(struct middleware_state* pState, const char* pGroupName)
{    
    struct rgcp_middleware_group* pGroup = calloc(sizeof(struct rgcp_middleware_group), 1);
    assert(pGroup);

    if (!pGroup)
    {
        log_msg(LOG_LEVEL_ERROR, "[Middleware] Failed to allocate group memory");
        return -1;
    }

    rgcp_middleware_group_init(pGroup, pGroupName, strlen(pGroupName));

    struct list_entry *pCurr, *pNext;
    LIST_FOR_EACH(pCurr, pNext, &pState->m_groupListHead)
    {
        struct rgcp_middleware_group* pCurrGroup = LIST_ENTRY(pCurr, struct rgcp_middleware_group, m_listEntry);
        if (pCurrGroup->m_groupNameInfo.m_groupNameHash == pGroup->m_groupNameInfo.m_groupNameHash)
            pGroup->m_groupNameInfo.m_groupNameHash++;
    }

    list_add_tail(&pGroup->m_listEntry, &pState->m_groupListHead);
    pState->m_numGroups++;
    log_msg(LOG_LEVEL_INFO, "[Middleware] Created new group (%s, 0x%x)\n", pGroupName, pGroup->m_groupNameInfo.m_groupNameHash);

    return 0;
}

size_t middleware_get_groups(struct middleware_state* pState, struct rgcp_middleware_group*** pppGroups)
{
    assert(pppGroups);
    (*pppGroups) = NULL;

    size_t count = 0;
    struct list_entry* pCurr, * pNext;
    LIST_FOR_EACH(pCurr, pNext, &pState->m_groupListHead)
    {
        count++;
        (*pppGroups) = realloc((*pppGroups), count * sizeof(struct rgcp_middleware_group*));
        (*pppGroups)[count - 1] = LIST_ENTRY(pCurr, struct rgcp_middleware_group, m_listEntry);
    }

    return count;
}

size_t middleware_get_clients_for_group(__attribute__((unused)) struct middleware_state* pState, __attribute__((unused)) struct rgcp_middleware_group* pGroup, __attribute__((unused)) struct client* pClients)
{
    // FIXME: implement
    return 0;
}

struct rgcp_group* middleware_get_group(__attribute__((unused)) struct middleware_state* pState, __attribute__((unused)) uint32_t groupHash)
{
    // FIXME: implement
    return NULL;
}

int middleware_group_exists(__attribute__((unused)) struct middleware_state* pState, __attribute__((unused)) uint32_t groupHash)
{
    // FIXME: implement
    return 0;
}

int main(__attribute__((unused)) int argc, __attribute__((unused)) char** argv)
{
    logger_init();
    if (middleware_state_init(&g_middlewareState, MIDDLEWARE_DEFAULT_PORT, MIDDLEWARE_DEFAULT_HEARTBEAT_TIMEOUT_SECONDS) < 0)
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