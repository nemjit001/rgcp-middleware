#ifndef RGCP_MIDDLEWARE_API_PACKET
#define RGCP_MIDDLEWARE_API_PACKET

#include <stdlib.h>
#include <stdint.h>

enum API_PACKET_TYPE
{
    API_HEARTBEAT_NOTIFY,
    API_GROUP_DISCOVERY,
    API_GROUP_JOIN,
    API_GROUP_LEAVE,
    API_GROUP_CREATE,
    API_PEER_SHARE,
    API_GROUP_SHARE,
    API_DISCONNECT
};

enum API_ERROR_TYPE
{
    API_NOERR       = 0,
    API_NOGRP       = 1,
    API_INGRP       = 2
};

struct api_packet
{
    enum API_PACKET_TYPE m_packetType;
    enum API_ERROR_TYPE m_errorType;
    size_t m_dataLen;
    uint8_t m_packetData[];
} __attribute__((packed));

int api_packet_init(struct api_packet** ppPacket, size_t dataLen);

void api_packet_free(struct api_packet* pPacket);

int api_packet_recv(int fd, struct api_packet** ppPacket);

int api_packet_send(int fd, struct api_packet* pPacket);

#endif
