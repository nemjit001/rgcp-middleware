#ifndef RGCP_MIDDLEWARE_API_PACKET
#define RGCP_MIDDLEWARE_API_PACKET

#include <stdlib.h>
#include <stdint.h>

enum API_PACKET_TYPE
{
    API_TYPE_NONE = 255
};

struct api_packet
{
    enum API_PACKET_TYPE m_packetType;
    size_t m_dataLen;
    uint8_t m_packetData[];
} __attribute__((packed));

void api_packet_init(struct api_packet** ppPacket, size_t dataLen);

void api_packet_free(struct api_packet* pPacket);

#endif
