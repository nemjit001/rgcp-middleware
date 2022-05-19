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
#define MIDDLEWARE_DEFAULT_HEARTBEAT_TIMEOUT_SECONDS 5
#define MIDDLEWARE_DEFAULT_GROUP_INACTIVE_TIMEOUT_SECONDS 60

static struct middleware_state g_middlewareState = { 0 };

static void handle_signal(int signum)
{
    if (signum & SIGINT)
    {
        g_middlewareState.m_shutdownFlag = 1;
    }

    // ignore SIGPIPE
    if (signum & SIGPIPE)
    {
        return;
    }
}

void _register_thread_signals()
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
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

int _send_middleware_groups(struct middleware_state* pState, struct client* pClient)
{
    struct rgcp_middleware_group** ppGroups = NULL;
    size_t groupCount = middleware_get_groups(pState, &ppGroups);
    
    uint8_t* pGroupInfoBuffer = NULL;
    ssize_t totalBufferSize = 0;
    for (size_t i = 0; i < groupCount; i++)
    {
        uint8_t* pTempBuffer = NULL;
        ssize_t ptrSize = serialize_rgcp_group_name_info((ppGroups[i]->m_groupNameInfo), &pTempBuffer);

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

    if (middleware_forward_packet_data(pClient, API_GROUP_DISCOVERY, API_ERROR_NOERR, pGroupInfoBuffer, totalBufferSize) < 0)
    {
        free(ppGroups);
        free(pGroupInfoBuffer);
        return -1;
    }

    free(ppGroups);
    free(pGroupInfoBuffer);
    return 0;
}

int _connect_to_group(struct client *pClient, struct rgcp_middleware_group *pGroup)
{
    assert(pGroup);

    if (pClient->m_connectionInfo.m_bConnectionInfoSet == 0)
    {
        log_msg(LOG_LEVEL_ERROR, "[Middleware] Client [%d] has no adress info set!\n", pClient->m_remoteFd);
        return -1;
    }

    if (pClient->m_pConnectedGroup == pGroup)
    {
        log_msg(LOG_LEVEL_DEBUG, "[Middleware] Client [%d] is already in group 0x%x\n", pClient->m_remoteFd, pGroup->m_groupNameInfo.m_groupNameHash);

        if (middleware_forward_packet_data(pClient, API_GROUP_JOIN, API_ERROR_INGRP, NULL, 0) < 0)
            return -1;

        return 0;
    }

    // get clients before registering new client
    struct client **ppGroupClients = NULL;
    size_t numClients = middleware_get_clients_for_group(pGroup, &ppGroupClients);

    if (rgcp_middleware_group_register_child(pGroup, (void*)pClient) < 0)
    {
        log_msg(LOG_LEVEL_ERROR, "[Middleware] Failed to register client [%d] to group [0x%x]\n", pClient->m_remoteFd, pGroup->m_groupNameInfo.m_groupNameHash);
        return -1;
    }

    struct _rgcp_peer_info clientPeerInfo;
    clientPeerInfo.m_addressInfo = pClient->m_connectionInfo.m_peerAddress;
    clientPeerInfo.m_addressLength = pClient->m_connectionInfo.m_addrLen;

    uint8_t* pClientAddrBuff = NULL;
    ssize_t clientAddrBuffLength = serialize_rgcp_peer_info(&clientPeerInfo, &pClientAddrBuff);

    if (clientAddrBuffLength < 0)
    {
        if (middleware_forward_packet_data(pClient, API_GROUP_JOIN, API_ERROR_SHARE, NULL, 0) < 0)
            return -1;

        return 0;
    }

    struct _rgcp_peer_info* pPeerInfos = calloc(numClients, sizeof(struct _rgcp_peer_info));
    assert(pPeerInfos);
    for (size_t i = 0; i < numClients; i++)
    {
        pPeerInfos[i].m_addressInfo = ppGroupClients[i]->m_connectionInfo.m_peerAddress;
        pPeerInfos[i].m_addressLength = ppGroupClients[i]->m_connectionInfo.m_addrLen;

        if (middleware_forward_packet_data(ppGroupClients[i], API_PEER_SHARE, API_ERROR_NOERR, pClientAddrBuff, clientAddrBuffLength) < 0)
        {
            free(ppGroupClients);
            free(pPeerInfos);
            free(pClientAddrBuff);

            // FIXME: try send ERROR_SHARE to remote and leave msg to group

            return 0;
        }
    }
    
    rgcp_group_t responseGroup;
    responseGroup.m_groupNameInfo = pGroup->m_groupNameInfo;
    responseGroup.m_peerList.m_pPeerInfos = pPeerInfos;
    responseGroup.m_peerList.m_peerInfoCount = numClients;

    uint8_t* pDataBuffer = NULL;
    ssize_t bufferSize = serialize_rgcp_group(&responseGroup, &pDataBuffer);
    free(ppGroupClients);
    free(pPeerInfos);
    free(pClientAddrBuff);

    if (bufferSize < 0)
    {
        // FIXME: send ERROR_SHARE to remote and leave msg to group
        return 0;
    }

    if (middleware_forward_packet_data(pClient, API_GROUP_SHARE, API_ERROR_NOERR, pDataBuffer, bufferSize) < 0)
    {
        // FIXME: send leave msg to group
        return -1;
    }

    pClient->m_pConnectedGroup = pGroup;
    free(pDataBuffer);
    return 0;
}

int _disconnect_from_group(struct middleware_state *pState, struct client* pClient, struct rgcp_middleware_group* pGroup)
{
    int success = 1;

    // TODO: check if actual middleware error, or we can just tell client it's disconnected
    if (!middleware_group_exists(pState, pGroup->m_groupNameInfo.m_groupNameHash))
        return -1;

    struct list_entry *pCurr, *pNext;
    LIST_FOR_EACH(pCurr, pNext, &pGroup->m_groupChildListHead)
    {
        struct rgcp_middleware_group_child *pCurrChild = LIST_ENTRY(pCurr, struct rgcp_middleware_group_child, m_listEntry);
        
        if (pCurrChild->pChild == pClient)
        {
            rgcp_middleware_group_delete_child(pGroup, pCurrChild);
            break;
        }
    }

    struct _rgcp_peer_info peerInfo;
    peerInfo.m_addressInfo = pClient->m_connectionInfo.m_peerAddress;
    peerInfo.m_addressLength = pClient->m_connectionInfo.m_addrLen;

    uint8_t *pDataBuffer = NULL;
    ssize_t bufferSize = serialize_rgcp_peer_info(&peerInfo, &pDataBuffer);

    if (!pDataBuffer || bufferSize < 0)
        return -1;

    LIST_FOR_EACH(pCurr, pNext, &pGroup->m_groupChildListHead)
    {
        struct rgcp_middleware_group_child *pCurrChild = LIST_ENTRY(pCurr, struct rgcp_middleware_group_child, m_listEntry);
        struct client *pCurrClient = (struct client*)pCurrChild->pChild;

        // error in ptrs
        if (pCurrClient->m_pSelf != pCurrClient)
        {
            // unrecoverable state
            success = 0;
            continue;
        }
        
        if (middleware_forward_packet_data(pCurrClient, API_GROUP_LEAVE, API_ERROR_NOERR, pDataBuffer, bufferSize) < 0)
        {
            // unrecoverable state
            success = 0;
            continue;
        }
    }

    if (middleware_forward_packet_data(pClient, API_GROUP_LEAVE_RESPONSE, API_ERROR_NOERR, NULL, 0) < 0)
    {
        // unrecoverable state
        success = 0;
    }
    
    free(pDataBuffer);
    return success ? 0 : -1;
}

int middleware_state_init(struct middleware_state* pState, uint16_t port, time_t heartbeatTimeoutSeconds, time_t groupActivityTimeoutSeconds)
{
    memset(pState, 0, sizeof(*pState));

    list_init(&(pState->m_childListHead));
    list_init(&(pState->m_groupListHead));

    pState->m_numClients = 0;
    pState->m_numGroups = 0;

    pState->m_listenSocket = -1;
    pState->m_listenSocket = _create_listen_socket(port);

    pState->m_heartbeatTimeout = heartbeatTimeoutSeconds;
    pState->m_groupActivityTimeout = groupActivityTimeoutSeconds;

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
        rgcp_middleware_group_free(pGroup);
        free(pGroup);
    }

    if (pState->m_pollingInfo.m_pollFds != NULL)
        free(pState->m_pollingInfo.m_pollFds);
}

int middleware_forward_packet_data(struct client* pClient, enum API_PACKET_TYPE packetType, enum API_ERROR_TYPE errorType, uint8_t* pPacketData, size_t dataLength)
{
    assert(pClient);

    if (pPacketData == NULL)
        dataLength = 0;

    struct api_packet* pPacket = NULL;
    if (api_packet_init(&pPacket, dataLength) < 0)
        return -1;
    
    if (pPacketData != NULL)
        memcpy(pPacket->m_packetData, pPacketData, dataLength);
    
    pPacket->m_errorType = errorType;
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
            log_msg(LOG_LEVEL_DEBUG, "[Middleware] Client [%d] has data for middleware\n", pClient->m_remoteFd);
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
        log_msg(LOG_LEVEL_ERROR, "[Middleware] Receive from Client [%d] has failed\n", pClient->m_remoteFd);
        return -1;
    }

    log_msg(LOG_LEVEL_DEBUG, "[Middleware] Received packet from Client [%d]: (%d, %d, %lu)\n", pClient->m_remoteFd, pPacket->m_packetType, pPacket->m_errorType, pPacket->m_dataLen);

    switch (pPacket->m_packetType)
    {
    case API_DISCONNECT:
    {
        if (middleware_forward_packet_data(pClient, API_DISCONNECT, API_ERROR_NOERR, NULL, 0) < 0)
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
        if (middleware_forward_packet_data(pClient, API_GROUP_CREATE, API_ERROR_NOERR, NULL, 0) < 0)
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
        rgcp_group_info_t groupInfo;
        if (deserialize_rgcp_group_name_info(&groupInfo, pPacket->m_packetData, pPacket->m_dataLen) < 0)
            goto error;
        
        log_msg(LOG_LEVEL_DEBUG, "[Middleware] Connection request for group [%s, 0x%x] from client [%d]\n", groupInfo.m_pGroupName, groupInfo.m_groupNameHash, pClient->m_remoteFd);

        if (middleware_group_exists(pState, groupInfo.m_groupNameHash) == 0)
        {
            log_msg(LOG_LEVEL_DEBUG, "[Middleware] Group with Hash 0x%x does not exist\n", groupInfo.m_groupNameHash);
            rgcp_group_info_free(groupInfo);

            if (middleware_forward_packet_data(pClient, API_GROUP_JOIN, API_ERROR_NOGRP, NULL, 0) < 0)
                goto error;

            break;
        }

        struct rgcp_middleware_group* pGroup = middleware_get_group(pState, groupInfo.m_groupNameHash);
        rgcp_group_info_free(groupInfo);
        assert(pGroup);

        if (_connect_to_group(pClient, pGroup) < 0)
        {
            // FIXME: remote in unrecoverable state, shut down client
            goto error;
        }
        
        break;
    }
    case API_GROUP_LEAVE:
    {
        // nothing to do
        if (pClient->m_pConnectedGroup == NULL)
            break;

        struct rgcp_middleware_group *pGroup = pClient->m_pConnectedGroup;
        
        if (_disconnect_from_group(pState, pClient, pGroup) < 0)
            goto error;

        pClient->m_pConnectedGroup = NULL;
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
        assert(pClient->m_pSelf == pClient);
        time_t currentTime = time(NULL);
        time_t delta = currentTime - pClient->m_lastHeartbeatTimestamp;
       
        if (pClient->m_shutdownFlag == 1 || delta > (2 * pState->m_heartbeatTimeout))
        {
            if (delta > (2 * pState->m_heartbeatTimeout))
            {
                pClient->m_shutdownFlag = 1;
                log_msg(LOG_LEVEL_ERROR, "[Middleware] Client[%d] shutting down, heartbeat message not received for 2 periods...\n", pClient->m_remoteFd);
            }

            if (pthread_join(pClient->m_threadHandle, NULL) < 0)
            {
                if (errno == EINTR)
                    continue;

                return -1;
            }

            if (pClient->m_pConnectedGroup != NULL)
            {
                if (_disconnect_from_group(pState, pClient, pClient->m_pConnectedGroup) < 0)
                    return -1;

                pClient->m_pConnectedGroup = NULL;
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
    LIST_FOR_EACH(pCurr, pNext, &(pState->m_groupListHead))
    {
        struct rgcp_middleware_group* pGroup = LIST_ENTRY(pCurr, struct rgcp_middleware_group, m_listEntry);

        time_t currentTime = time(NULL);
        time_t delta = currentTime - pGroup->m_lastActivityTimestamp;

        if (delta > pState->m_groupActivityTimeout && pGroup->m_childCount == 0)
        {
            log_msg(LOG_LEVEL_INFO, "[Middleware] Deleted Group (%s, 0x%x) due to inactivity and no connected clients\n", pGroup->m_groupNameInfo.m_pGroupName, pGroup->m_groupNameInfo.m_groupNameHash);

            list_del(pCurr);
            rgcp_middleware_group_free(pGroup);
            free(pGroup);
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

size_t middleware_get_clients_for_group(struct rgcp_middleware_group* pGroup, struct client*** pppClients)
{
    assert(pGroup);
    assert(pppClients);

    (*pppClients) = NULL;
    (*pppClients) = calloc(pGroup->m_childCount, sizeof(struct client*));

    size_t idx = 0;
    struct list_entry *pCurr, *pNext;
    LIST_FOR_EACH(pCurr, pNext, &pGroup->m_groupChildListHead)
    {
        struct rgcp_middleware_group_child *pCurrChild = LIST_ENTRY(pCurr, struct rgcp_middleware_group_child, m_listEntry);
        
        (*pppClients)[idx] = (struct client*)(pCurrChild->pChild);
        assert((*pppClients)[idx] == (*pppClients)[idx]->m_pSelf);

        if ((*pppClients)[idx] != (*pppClients)[idx]->m_pSelf)
            return -1;

        idx++;
    }

    return pGroup->m_childCount;
}

struct rgcp_middleware_group* middleware_get_group(struct middleware_state* pState, uint32_t groupHash)
{
    struct list_entry *pCurr, *pNext;
    LIST_FOR_EACH(pCurr, pNext, &(pState->m_groupListHead))
    {
        struct rgcp_middleware_group* pGroup = LIST_ENTRY(pCurr, struct rgcp_middleware_group, m_listEntry);
        assert(pGroup);
        
        if (pGroup->m_groupNameInfo.m_groupNameHash == groupHash)
            return pGroup;
    }

    return NULL;
}

int middleware_group_exists(struct middleware_state* pState, uint32_t groupHash)
{
    struct list_entry *pCurr, *pNext;
    LIST_FOR_EACH(pCurr, pNext, &(pState->m_groupListHead))
    {
        struct rgcp_middleware_group* pGroup = LIST_ENTRY(pCurr, struct rgcp_middleware_group, m_listEntry);
        assert(pGroup);
        
        if (pGroup->m_groupNameInfo.m_groupNameHash == groupHash)
            return 1;
    }

    return 0;
}

int main(__attribute__((unused)) int argc, __attribute__((unused)) char** argv)
{
    logger_init();
    if (middleware_state_init(&g_middlewareState, MIDDLEWARE_DEFAULT_PORT, MIDDLEWARE_DEFAULT_HEARTBEAT_TIMEOUT_SECONDS, MIDDLEWARE_DEFAULT_GROUP_INACTIVE_TIMEOUT_SECONDS) < 0)
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
        
        if (middleware_check_group_states(&g_middlewareState) < 0)
            break;
    } 

    log_msg(LOG_LEVEL_INFO, "[Middleware] Shutting Down Middleware...\n");
    middleware_state_free(&g_middlewareState);
    logger_free();

    return 0;
}