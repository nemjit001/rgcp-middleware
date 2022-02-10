#include "api_packet.h"

#include <string.h>
#include <assert.h>

void api_packet_init(struct api_packet** ppPacket, size_t dataLen)
{
    assert(ppPacket);

    size_t ptr_size = sizeof(struct api_packet) + (dataLen * sizeof(uint8_t));
    (*ppPacket) = NULL;
    (*ppPacket) = malloc(ptr_size);

    assert((*ppPacket));
    memset(*ppPacket, 0, ptr_size);
}

void api_packet_free(struct api_packet* pPacket)
{
    assert(pPacket);
    free(pPacket);
}
