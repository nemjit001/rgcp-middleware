#ifndef RGCP_WORKERAPI_H
#define RGCP_WORKERAPI_H

#include "system_headers.h"

enum workerapi_req_type
{
    WORKERAPI_ADDR_INFO_SHARE,
    WORKERAPI_GROUP_CREATE,
    WORKERAPI_GROUP_CREATE_OK,
    WORKERAPI_GROUP_CREATE_ERROR_NAME,
    WORKERAPI_GROUP_CREATE_ERROR_MAX_GROUPS,
    WORKERAPI_GROUP_CREATE_ERROR_EXISTS,
    WORKERAPI_GROUP_DISCOVER,
    WORKERAPI_GROUP_DISCOVER_RESPONSE,
    WORKERAPI_GROUP_JOIN,
    WORKERAPI_GROUP_JOIN_ERROR_MAX_CLIENTS,
    WORKERAPI_GROUP_JOIN_ERROR_NO_SUCH_GROUP,
    WORKERAPI_GROUP_JOIN_ERROR_NAME,
    WORKERAPI_GROUP_JOIN_ERROR_ALREADY_IN_GROUP,
    WORKERAPI_GROUP_JOIN_RESPONSE,
    WORKERAPI_NEW_GROUP_MEMBER,
    WORKERAPI_GROUP_LEAVE,
    WORKERAPI_DELETE_GROUP_MEMBER
};

struct rgcp_workerapi_packet
{
    uint32_t packet_len;
    enum workerapi_req_type type;
    uint8_t data[];
} __attribute__((packed));

int workerapi_send(int fd, struct rgcp_workerapi_packet *packet);

int workerapi_recv(int fd, struct rgcp_workerapi_packet **packet);

#endif // RGCP_WORKERAPI_H
