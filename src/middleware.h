#ifndef RGCP_MIDDLEWARE
#define RGCP_MIDDLEWARE

#include <poll.h>

#include "client.h"
#include "details/linked_list.h"

struct middleware_state
{
    struct list_entry m_groupListHead;
    struct list_entry m_childListHead;

    size_t m_numGroups;
    size_t m_numClients;

    int m_listenSocket;
    int m_shutdownFlag;

    time_t m_heartbeatTimeout;
    time_t m_groupActivityTimeout;

    struct 
    {
        struct pollfd* m_pollFds;
        size_t m_pollFdSize;
    } m_pollingInfo;
};

int middleware_state_init(struct middleware_state* pState, uint16_t port, time_t heartbeatTimeoutSeconds, time_t groupActivityTimeoutSeconds);

void middleware_state_free(struct middleware_state* pState);

int middleware_forward_packet_data(struct client* pClient, enum API_PACKET_TYPE packetType, enum API_ERROR_TYPE errorType, uint8_t* pPacketData, size_t dataLength);

int middleware_handle_incoming(struct middleware_state* pState);

int middleware_handle_client_message(struct middleware_state* pState, struct client *pClient);

int middleware_check_client_states(struct middleware_state* pState);

int middleware_check_group_states(struct middleware_state* pState);

int middleware_handle_new_connection(struct middleware_state* pState);

int middleware_handle_new_group(struct middleware_state* pState, const char* pGroupName);

size_t middleware_get_groups(struct middleware_state* pState, struct rgcp_middleware_group*** pppGroups);

size_t middleware_get_clients_for_group(struct rgcp_middleware_group* pGroup, struct client*** pppClients);

struct rgcp_middleware_group* middleware_get_group(struct middleware_state* pState, uint32_t groupHash);

int middleware_group_exists(struct middleware_state* pState, uint32_t groupHash);

#endif