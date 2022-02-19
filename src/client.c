#include "client.h"

#include <assert.h>
#include <unistd.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <rgcp/rgcp_peer.h>

#include "details/logger.h"

int client_init(struct client* pClient, struct sockaddr_in peerAddress, int remoteFd)
{
    assert(pClient);
    pClient->m_lastHeartbeatTimestamp = time(NULL);
    pClient->m_threadHandle = 0;
    pClient->m_shutdownFlag = 0;
    pClient->m_remoteFd = remoteFd;
    pClient->m_connectionInfo.m_bConnectionInfoSet = 0;
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

int client_set_heartbeat_timestamp(struct client* pClient)
{
    time_t timestamp = time(NULL);

    assert(timestamp > pClient->m_lastHeartbeatTimestamp);
    if (timestamp < pClient->m_lastHeartbeatTimestamp)
        return -1;

    return 0;
}

int client_register_host_data(struct client* pClient, struct rgcp_packet* pPacket)
{
    assert(pClient);
    assert(pPacket);
    
    struct _rgcp_peer_info peerInfo;
    memset(&peerInfo, 0, sizeof(struct _rgcp_peer_info));

    if (deserialize_rgcp_peer_info(&peerInfo, pPacket->m_data, pPacket->m_dataLen) < 0)
        return -1;

    if (pClient->m_connectionInfo.m_bConnectionInfoSet)
        return 0;

    pClient->m_connectionInfo.m_addrLen = peerInfo.m_addressLength;
    pClient->m_connectionInfo.m_peerAddress = peerInfo.m_addressInfo;
    pClient->m_connectionInfo.m_bConnectionInfoSet = 1;

    return 0;
}

int client_forward_packet_data(struct client* pClient, enum API_PACKET_TYPE packetType, uint8_t* pPacketData, size_t dataLength)
{
    assert(pClient);

    struct api_packet* pPacket = NULL;

    if (api_packet_init(&pPacket, dataLength) < 0)
        return -1;

    pPacket->m_packetType = packetType;
    pPacket->m_errorType = 0;

    if (pPacketData)
    {
        pPacket->m_dataLen = dataLength;
        memcpy(pPacket->m_packetData, pPacket, dataLength);
    }
    else
    {
        pPacket->m_dataLen = 0;
    }

    if (api_packet_send(pClient->m_communicationSockets.m_mainThreadSocket, pPacket) < 0)
    {
        api_packet_free(pPacket);
        return -1;
    }

    api_packet_free(pPacket);

    return 0;
}

int client_process_remote_packet(struct client* pClient, struct rgcp_packet* pPacket)
{
    assert(pClient);
    assert(pPacket);
    assert(pPacket->m_packetError == 0);

    switch(pPacket->m_packetType)
    {
    case RGCP_TYPE_HEARTBEAT_NOTIFY:
        return client_set_heartbeat_timestamp(pClient);
    case RGCP_TYPE_SOCKET_CONNECT:
        return client_register_host_data(pClient, pPacket);
    case RGCP_TYPE_SOCKET_DISCONNECT:
        return client_forward_packet_data(pClient, API_DISCONNECT, pPacket->m_data, pPacket->m_dataLen);
    case RGCP_TYPE_GROUP_DISCOVER:
        return client_forward_packet_data(pClient, API_GROUP_DISCOVERY, NULL, 0);
    case RGCP_TYPE_GROUP_CREATE:
        return client_forward_packet_data(pClient, API_GROUP_CREATE, pPacket->m_data, pPacket->m_dataLen);
    case RGCP_TYPE_GROUP_JOIN:
        return client_forward_packet_data(pClient, API_GROUP_JOIN, NULL, 0);
    case RGCP_TYPE_GROUP_LEAVE:
        return client_forward_packet_data(pClient, API_GROUP_LEAVE, NULL, 0);
    // Below are invalid types, return error
    case RGCP_TYPE_GROUP_DISCOVER_RESPONSE:
    case RGCP_TYPE_GROUP_CREATE_RESPONSE:
    case RGCP_TYPE_GROUP_JOIN_RESPONSE:
    case RGCP_TYPE_PEER_REMOVE:
    case RGCP_TYPE_PEER_SHARE:
        log_msg(LOG_LEVEL_ERROR, "[Client][%d] Received invalid Packet Type (%d)\n", pClient->m_remoteFd, pPacket->m_packetType);
        return -1;
    }

    return 0;
}

int client_handle_remote_message(struct client* pClient)
{
    struct rgcp_packet* pPacket = NULL;

    if (rgcp_api_recv(pClient->m_remoteFd, &pPacket) < 0)
        goto error;

    if (!pPacket)
    {
        log_msg(LOG_LEVEL_ERROR, "[Client][%d] Received Empty Packet from Remote\n", pClient->m_remoteFd);
        goto error;
    }

    log_msg(LOG_LEVEL_DEBUG, "[Client][%d] Received Remote Packet (%d, %d, %u)\n", pClient->m_remoteFd, pPacket->m_packetType, pPacket->m_packetError, pPacket->m_dataLen);

    if (client_process_remote_packet(pClient, pPacket) < 0)
        goto error;

    rgcp_packet_free(pPacket);
    return 0;

error:
    if (pPacket)
        rgcp_packet_free(pPacket);
    return -1;
}

int client_handle_main_thread_message(struct client* pClient)
{
    struct api_packet* pPacket = NULL;

    if (api_packet_recv(pClient->m_communicationSockets.m_mainThreadSocket, &pPacket) < 0)
        return -1;

    log_msg(LOG_LEVEL_DEBUG, "[Client][%d] Received Main Thread Packet (%d, %d, %u)\n", pClient->m_remoteFd, pPacket->m_packetType, pPacket->m_errorType, pPacket->m_dataLen);

    switch (pPacket->m_packetType)
    {
    case API_HEARTBEAT_NOTIFY:
        // should not receive heartbeat notify from main thread, something went wrong
        goto error;
    case API_GROUP_DISCOVERY:
        // response to group discovery, send to remote
        break;
    case API_GROUP_JOIN:
        // response to group join, send to remote
        break;
    case API_GROUP_LEAVE:
        // response to group leave, send to remote
        break;
    case API_GROUP_CREATE:
        // response to group creation, send to remote
        break;
    case API_PEER_SHARE:
        // new member, send to remote
        break;
    case API_GROUP_SHARE:
        // group info, send to remote
        break;
    case API_DISCONNECT:
        // group member disconnect, send to remote
        break;
    default:
        log_msg(LOG_LEVEL_ERROR, "[Client][%d] Received Main Thread Packet with Invalid Type: %d\n", pClient->m_remoteFd);
        goto error;
    }

    api_packet_free(pPacket);
    return 0;

error:
    api_packet_free(pPacket);
    return -1;
}

int client_handle_incoming(struct client* pClient)
{
    int successFlag = 1;
    
    struct pollfd remote;
    remote.fd = pClient->m_remoteFd;
    remote.events = POLLIN;
    remote.revents = 0;

    struct pollfd mainThread;
    mainThread.fd = pClient->m_communicationSockets.m_mainThreadSocket;
    mainThread.events = POLLIN;
    mainThread.revents = 0;

    struct pollfd pollFds[2] = { remote, mainThread };

    if (poll(pollFds, 2, 0) < 0)
    {
        if (errno != EINTR)
        {
            perror("Client Thread FD Polling failed");
            successFlag = 0;
        }
    }

    remote = pollFds[0];
    mainThread = pollFds[1];

    if (remote.revents & (POLLNVAL) || mainThread.revents & (POLLNVAL))
    {
        log_msg(LOG_LEVEL_ERROR, "[Client][%d] Polling on Sockets returned Invalid\n", pClient->m_remoteFd);
        successFlag = 0;
    }

    if (remote.revents & POLLRDHUP || remote.revents & POLLERR)
    {
        // remote closed
        log_msg(LOG_LEVEL_INFO, "[Client][%d] Remote Closed\n", pClient->m_remoteFd);
        pClient->m_shutdownFlag = 1;
        return successFlag;
    }
    else if (remote.revents & POLLIN)
    {
        log_msg(LOG_LEVEL_DEBUG, "[Client][%d] Remote Has Data Available\n", pClient->m_remoteFd);
        if (client_handle_remote_message(pClient) < 0)
            successFlag = 0;
    }

    if (mainThread.revents & POLLHUP || mainThread.revents & POLLERR)
    {
        // remote closed
        log_msg(LOG_LEVEL_DEBUG, "[Client][%d] Main Thread Socket Closed\n", pClient->m_remoteFd);
        pClient->m_shutdownFlag = 1;
        return successFlag;
    }
    else if (mainThread.revents & POLLIN)
    {
        log_msg(LOG_LEVEL_DEBUG, "[Client][%d] Main Thread Has Data Available\n", pClient->m_remoteFd);
        if (client_handle_main_thread_message(pClient) < 0)
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
            log_msg(LOG_LEVEL_ERROR, "[Client][%d] Failed to handle message, shutting down thread...\n", pClient->m_remoteFd);
            pClient->m_shutdownFlag = 1;
        }
    }

    log_msg(LOG_LEVEL_INFO, "[Client][%d] Shut Down Client Thread...\n", pClient->m_remoteFd);

    return NULL;
}