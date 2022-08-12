#include "api_packet.h"

#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "logger.h"

int api_packet_init(struct api_packet** ppPacket, size_t dataLen)
{
    assert(ppPacket);

    size_t ptrSize = sizeof(struct api_packet) + (dataLen * sizeof(uint8_t));
    (*ppPacket) = NULL;
    (*ppPacket) = malloc(ptrSize);

    assert((*ppPacket));
    if ((*ppPacket) == NULL)
        return -1;

    memset(*ppPacket, 0, ptrSize);
    return 0;
}

void api_packet_free(struct api_packet* pPacket)
{
    assert(pPacket);
    free(pPacket);
}

int api_packet_recv(int fd, struct api_packet** ppPacket)
{
    assert(fd >= 0);
    assert(ppPacket);

    uint32_t packetLength = 0;
    if (read(fd, &packetLength, sizeof(uint32_t)) < 0)
        return -1;

    if (packetLength == 0)
        return 0;
    
    uint8_t* buffer = calloc(packetLength, sizeof(uint8_t));
    if (!buffer)
        return -1;

    if (read(fd, buffer, packetLength) < 0)
    {
        free(buffer);
        return -1;
    }
    
    if (api_packet_init(ppPacket, packetLength) < 0)
    {
        free(buffer);
        return -1;
    }
    
    memcpy(*ppPacket, buffer, packetLength);
    free(buffer);

    return packetLength;
}

int api_packet_send(int fd, struct api_packet* pPacket)
{
    assert(fd >= 0);
    assert(pPacket);

    uint32_t packetSize = sizeof(struct api_packet) + pPacket->m_dataLen;
    uint8_t* buffer = calloc(packetSize, sizeof(uint8_t));

    if (!buffer)
        return -1;

    memcpy(buffer, pPacket, packetSize);

    if (write(fd, &packetSize, sizeof(uint32_t)) < 0)
    {
        free(buffer);
        return -1;
    }
    
    if (write(fd, buffer, packetSize) < 0)
    {
        free(buffer);
        return -1;
    }

    free(buffer);
    return packetSize;
}
