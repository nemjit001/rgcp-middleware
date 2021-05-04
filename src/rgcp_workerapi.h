#ifndef RGCP_WORKERAPI_H
#define RGCP_WORKERAPI_H

#include "system_headers.h"

struct rgcp_workerapi_packet
{
    size_t datalen;
    uint8_t data[];
} __attribute__((packed));

#endif // RGCP_WORKERAPI_H
