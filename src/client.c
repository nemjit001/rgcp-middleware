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
    pClient->m_connectionInfo.m_peerAddress.sin_port = 0; // needs to be set later
    pClient->m_connectionInfo.m_addrLen = sizeof(peerAddress);

    if (pthread_mutex_init(&pClient->m_apiMtxes.m_sendMtx, NULL) < 0 || pthread_mutex_init(&pClient->m_apiMtxes.m_recvMtx, NULL) < 0)
        return -1;

    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0)
        return -1;

    pClient->m_communicationSockets.m_mainThreadSocket = sockets[0];
    pClient->m_communicationSockets.m_clientThreadSocket = sockets[1];

    pClient->m_pConnectedGroup = NULL;
    pClient->m_pSelf = pClient;
    return 0;
}

void client_free(struct client client)
{
    pthread_mutex_destroy(&client.m_apiMtxes.m_sendMtx);
    pthread_mutex_destroy(&client.m_apiMtxes.m_recvMtx);

    close(client.m_communicationSockets.m_mainThreadSocket);
    close(client.m_communicationSockets.m_clientThreadSocket);
    shutdown(client.m_remoteFd, SHUT_RDWR);
    close(client.m_remoteFd);
}

int client_set_heartbeat_timestamp(struct client* pClient)
{
    time_t timestamp = time(NULL);

    assert(timestamp >= pClient->m_lastHeartbeatTimestamp);
    if (timestamp < pClient->m_lastHeartbeatTimestamp)
        return -1;

    log_msg(LOG_LEVEL_DEBUG, "[Client][%d] <3\n", pClient->m_remoteFd);
    pClient->m_lastHeartbeatTimestamp = timestamp;

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
    pClient->m_connectionInfo.m_peerAddress.sin_port = peerInfo.m_addressInfo.sin_port; // only set the port, other fields have been set by middleware on connection
    pClient->m_connectionInfo.m_bConnectionInfoSet = 1;

    char* ipaddrstr = inet_ntoa(pClient->m_connectionInfo.m_peerAddress.sin_addr);
    log_msg(LOG_LEVEL_DEBUG, "[Client][%d] Peer Connection Data: %s:%u\n", pClient->m_remoteFd, ipaddrstr, peerInfo.m_addressInfo.sin_port);

    return 0;
}

int client_forward_packet_data(struct client* pClient, enum API_PACKET_TYPE packetType, uint8_t* pPacketData, size_t dataLength)
{
    assert(pClient);

    if (pPacketData == NULL)
        dataLength = 0;

    struct api_packet* pPacket = NULL;
    if (api_packet_init(&pPacket, dataLength) < 0)
        return -1;

    pPacket->m_packetType = packetType;
    pPacket->m_errorType = 0;

    if (pPacketData)
        memcpy(pPacket->m_packetData, pPacketData, dataLength);

    pPacket->m_dataLen = dataLength;

    if (api_packet_send(pClient->m_communicationSockets.m_mainThreadSocket, pPacket) < 0)
    {
        api_packet_free(pPacket);
        return -1;
    }

    api_packet_free(pPacket);

    return 0;
}

int client_send_packet_to_remote(int fd, pthread_mutex_t* pMtx, enum RGCP_PACKET_TYPE packetType, enum RGCP_PACKET_ERROR error, uint8_t* pPacketData, size_t dataLength)
{
    assert(pMtx);

    if (pPacketData == NULL)
        dataLength = 0;
    
    struct rgcp_packet* pPacket = NULL;
    if (rgcp_packet_init(&pPacket, dataLength) < 0)
        return -1;

    assert(pPacket);

    pPacket->m_packetType = packetType;
    pPacket->m_packetError = error;
    pPacket->m_dataLen = dataLength;

    if (pPacketData != NULL)
        memcpy(pPacket->m_data, pPacketData, dataLength);

    if (rgcp_api_send(fd, pMtx, pPacket) < 0)
    {
        rgcp_packet_free(pPacket);
        return -1;
    }
    
    rgcp_packet_free(pPacket);
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
        return client_forward_packet_data(pClient, API_GROUP_JOIN, pPacket->m_data, pPacket->m_dataLen);
    case RGCP_TYPE_GROUP_LEAVE:
        return client_forward_packet_data(pClient, API_GROUP_LEAVE, NULL, 0);
    // Below are invalid types, return error
    case RGCP_TYPE_SOCKET_DISCONNECT_RESPONSE:
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

    if (rgcp_api_recv(pClient->m_remoteFd, &pClient->m_apiMtxes.m_recvMtx, &pPacket) < 0)
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

    enum RGCP_PACKET_ERROR packetError = RGCP_ERROR_NO_ERROR;
    switch (pPacket->m_errorType)
    {
        case API_ERROR_INGRP:
            packetError = RGCP_ERROR_ALREADY_IN_GROUP;
            break;
        case API_ERROR_NOGRP:
            packetError = RGCP_ERROR_NO_SUCH_GROUP;
            break;
        case API_ERROR_SHARE:
            packetError = RGCP_ERROR_SHARING_ERROR;
            break;
        case API_ERROR_NOERR:
        default:
            break;
    }

    switch (pPacket->m_packetType)
    {
    case API_HEARTBEAT_NOTIFY:
        // should not receive heartbeat notify from main thread, something went wrong
        goto error;
    case API_GROUP_DISCOVERY:
    // response to group discovery, send to remote
    {
        if (client_send_packet_to_remote(pClient->m_remoteFd, &pClient->m_apiMtxes.m_sendMtx, RGCP_TYPE_GROUP_DISCOVER_RESPONSE, packetError, pPacket->m_packetData, pPacket->m_dataLen) < 0)
            goto error;
        
        break;
    }
    case API_GROUP_JOIN:
    {
        // response to group join, only contains error data
        if (client_send_packet_to_remote(pClient->m_remoteFd, &pClient->m_apiMtxes.m_sendMtx, RGCP_TYPE_GROUP_JOIN_RESPONSE, packetError, NULL, 0) < 0)
            goto error;

        break;
    }
    case API_GROUP_LEAVE:
        // peer left group, send to remote
        if (client_send_packet_to_remote(pClient->m_remoteFd, &pClient->m_apiMtxes.m_sendMtx, RGCP_TYPE_PEER_REMOVE, packetError, pPacket->m_packetData, pPacket->m_dataLen) < 0)
            goto error;

        break;
    case API_GROUP_CREATE:
    {
        if (client_send_packet_to_remote(pClient->m_remoteFd, &pClient->m_apiMtxes.m_sendMtx, RGCP_TYPE_GROUP_CREATE_RESPONSE, packetError, NULL, 0) < 0)
            goto error;

        break;
    }
    case API_PEER_SHARE:
    {
        if (client_send_packet_to_remote(pClient->m_remoteFd, &pClient->m_apiMtxes.m_sendMtx, RGCP_TYPE_PEER_SHARE, packetError, pPacket->m_packetData, pPacket->m_dataLen) < 0)
            goto error;

        break;
    }
    case API_GROUP_SHARE:
    {
        if (client_send_packet_to_remote(pClient->m_remoteFd, &pClient->m_apiMtxes.m_sendMtx, RGCP_TYPE_GROUP_JOIN_RESPONSE, packetError, pPacket->m_packetData, pPacket->m_dataLen) < 0)
            goto error;

        break;
    }
    case API_DISCONNECT:
    {
        if (client_send_packet_to_remote(pClient->m_remoteFd, &pClient->m_apiMtxes.m_sendMtx, RGCP_TYPE_SOCKET_DISCONNECT_RESPONSE, packetError, NULL, 0) < 0)
            goto error;

        break;
    }
    default:
        log_msg(LOG_LEVEL_ERROR, "[Client][%d] Received Main Thread Packet with Invalid Type: %d\n", pClient->m_remoteFd, pPacket->m_packetType);
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
    remote.events = POLLIN | POLLRDHUP;
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
        log_msg(LOG_LEVEL_DEBUG, "[Client][%d] Remote Closed\n", pClient->m_remoteFd);
        pClient->m_shutdownFlag = 1;
    }
    else if (remote.revents & POLLIN)
    {
        log_msg(LOG_LEVEL_DEBUG, "[Client][%d] Remote Has Data Available\n", pClient->m_remoteFd);
        if (client_handle_remote_message(pClient) < 0)
        {
            // cannot handle packet due to error, drop and continue;
            successFlag = 1;
        }
    }

    if (mainThread.revents & POLLHUP || mainThread.revents & POLLERR)
    {
        // remote closed
        log_msg(LOG_LEVEL_DEBUG, "[Client][%d] Main Thread Socket Closed\n", pClient->m_remoteFd);
        pClient->m_shutdownFlag = 1;
    }
    else if (mainThread.revents & POLLIN)
    {
        log_msg(LOG_LEVEL_DEBUG, "[Client][%d] Main Thread Has Data Available\n", pClient->m_remoteFd);
        if (client_handle_main_thread_message(pClient) < 0)
        {
            // cannot handle packet due to comms error between client and main thread, or client and remote. Drop and error out.
            successFlag = 0;
        }
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

    log_msg(LOG_LEVEL_DEBUG, "[Client][%d] Initialized Client Thread...\n", pClient->m_remoteFd);

    while(pClient->m_shutdownFlag == 0)
    {
        if (client_handle_incoming(pClient) == 0)
        {
            log_msg(LOG_LEVEL_ERROR, "[Client][%d] Failed to handle message, shutting down thread...\n", pClient->m_remoteFd);
            pClient->m_shutdownFlag = 1;
        }
    }

    log_msg(LOG_LEVEL_DEBUG, "[Client][%d] Shut Down Client Thread...\n", pClient->m_remoteFd);

    return NULL;
}