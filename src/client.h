#ifndef RGCP_MIDDLEWARE_CLIENT
#define RGCP_MIDDLEWARE_CLIENT

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <sys/socket.h>
#include <rgcp/rgcp_api.h>

#include "details/rgcp_group.h"
#include "details/linked_list.h"

struct client
{    
    struct list_entry m_listEntry;
    pthread_t m_threadHandle;
    time_t m_lastHeartbeatTimestamp;

    int m_shutdownFlag;
    int m_remoteFd;

    struct
    {
        int m_mainThreadSocket;
        int m_clientThreadSocket;
    } m_communicationSockets;

    struct
    {
        struct sockaddr_in m_peerAddress;
        socklen_t m_addrLen;
    } m_connectionInfo;

    struct client* m_pSelf;
};

int client_init(struct client* pClient, struct sockaddr_in peerAddress, int remoteFd);

void client_free(struct client client);

int client_register_host_data(struct client* pClient, struct rgcp_packet* pPacket);

int client_process_remote_packet(struct client* pClient, struct rgcp_packet* pPacket);

int client_handle_remote_message(struct client* pClient);

int client_handle_main_thread_message(struct client* pClient);

int client_handle_incoming(struct client* pClient);

void *client_thread_main(void *pClient);

#endif 