#include <stdio.h>
#include "system_headers.h"
#include "rgcp_utils.h"
#include "rgcp_worker.h"
#include "rgcp_workerapi.h"

struct worker_state
{
    int serverfd;
    int clientfd;
    int eof;
};

void worker_state_init(struct worker_state *state, int clientfd, int serverfd)
{
    memset(state, 0, sizeof(*state));

    state->clientfd = clientfd;
    state->serverfd = serverfd;
}

void worker_state_free(struct worker_state *state)
{
    assert(state);
    close(state->clientfd);
    close(state->serverfd);
}

int client_recv(int fd, struct rgcp_packet **packet)
{
    assert(fd >= 0);
    assert(*packet == NULL);

    uint8_t size_buffer[sizeof(uint32_t)];
    int res1 = recv(fd, size_buffer, sizeof(uint32_t), 0);

    // If error remote client has exited unexpectedly or closed socket incorrectly
    if (res1 < 0)
        return -1;

    // client closed normally
    if (res1 == 0)
        return 0;

    uint32_t packet_length = *((uint32_t *)size_buffer);

    // erronous packet length received, probably due to client crash
    if (packet_length == 0)
        return -1;

    uint8_t data_buffer[packet_length - sizeof(uint32_t)];
    int res2 = recv(fd, data_buffer, packet_length - sizeof(uint32_t), 0);

    // second recv call empty check
    if (res2 < 0)
        return -1;

    uint8_t packet_buffer[packet_length];

    // copying over to relevant pointer offsets
    memcpy(packet_buffer, size_buffer, sizeof(uint32_t));
    memcpy(packet_buffer + sizeof(uint32_t), data_buffer, packet_length - sizeof(uint32_t));

    *packet = calloc(packet_length, 1);

    if (packet == NULL)
    {
        perror("Calloc of packet in client recv has failed");
        return -1;
    }

    memcpy(*packet, packet_buffer, packet_length);

    return res1 + res2;
}

int client_send(int fd, struct rgcp_packet *packet)
{
    assert(fd >= 0);
    assert(packet);

    ssize_t packet_size_bytes = send(fd, (uint8_t *)packet, packet->packet_len, 0);

    // If empty or error remote client has exited or closed socket
    if (packet_size_bytes < 0)
        return -1;

    return packet_size_bytes;
}

int send_workerapi_request_no_data(struct worker_state *state, enum workerapi_req_type type)
{
    struct rgcp_workerapi_packet packet;
    memset(&packet, 0, sizeof(packet));

    packet.type = type;
    packet.packet_len = sizeof(packet);

    return workerapi_send(state->serverfd, &packet);
}

int send_workerapi_request_with_data(struct worker_state *state, struct rgcp_packet *packet)
{
    assert(state);
    assert(packet);

    int datalen = packet->packet_len - sizeof(*packet);
    int packet_len = datalen + sizeof(struct rgcp_workerapi_packet);

    struct rgcp_workerapi_packet *worker_packet = calloc(packet_len, 1);

    if (packet == NULL)
    {
        perror("Calloc of packet in \"send workerapi request with data\" has failed");
        return -1;
    }

    switch (packet->type)
    {
    case RGCP_ADDRINFO_SHARE:
        worker_packet->type = WORKERAPI_ADDR_INFO_SHARE;
        break;
    case RGCP_CREATE_GROUP:
        worker_packet->type = WORKERAPI_GROUP_CREATE;
        break;
    case RGCP_JOIN_GROUP:
        worker_packet->type = WORKERAPI_GROUP_JOIN;
        break;
    case RGCP_LEAVE_GROUP:
        worker_packet->type = WORKERAPI_GROUP_LEAVE;
        break;
    default:
        free(worker_packet);
        return -1;
    }

    worker_packet->packet_len = packet_len;
    memcpy(worker_packet->data, packet->data, datalen);

    int retval = workerapi_send(state->serverfd, worker_packet);

    free(worker_packet);

    return retval < 0 ? -1 : 0;
}

int execute_client_request(struct worker_state *state, struct rgcp_packet *packet)
{
    assert(state);
    assert(packet);

    switch(packet->type)
    {
    case RGCP_GROUP_DISCOVER:
        return send_workerapi_request_no_data(state, WORKERAPI_GROUP_DISCOVER);
    case RGCP_ADDRINFO_SHARE:
    case RGCP_CREATE_GROUP:
    case RGCP_JOIN_GROUP:
    case RGCP_LEAVE_GROUP:
        return send_workerapi_request_with_data(state, packet);
    default:
        break;
    }

    return 0;
}

int execute_server_request(struct worker_state *state, struct rgcp_workerapi_packet *packet)
{
    assert(state);
    assert(packet);

    int success = 1;
    uint32_t datalen = packet->packet_len - sizeof(struct rgcp_workerapi_packet);

    struct rgcp_packet *client_packet = calloc(datalen + sizeof(struct rgcp_packet), 1);

    if (packet == NULL)
    {
        perror("Calloc of packet in execute server request has failed");
        return -1;
    }

    memset(client_packet, 0, sizeof(struct rgcp_packet) + datalen);
    client_packet->packet_len = datalen + sizeof(struct rgcp_packet);
    memcpy(client_packet->data, packet->data, datalen);

    switch(packet->type)
    {
    case WORKERAPI_GROUP_DISCOVER_RESPONSE:
        client_packet->type = RGCP_GROUP_DISCOVER_RESPONSE;
        break;
    case WORKERAPI_NEW_GROUP_MEMBER:
        client_packet->type = RGCP_NEW_GROUP_MEMBER;
        break;
    case WORKERAPI_DELETE_GROUP_MEMBER:
        client_packet->type = RGCP_DELETE_GROUP_MEMBER;
        break;
    case WORKERAPI_GROUP_CREATE_OK:
        client_packet->type = RGCP_CREATE_GROUP_OK;
        break;
    case WORKERAPI_GROUP_CREATE_ERROR_MAX_GROUPS:
        client_packet->type = RGCP_CREATE_GROUP_ERROR_MAX_GROUPS;
        break;
    case WORKERAPI_GROUP_CREATE_ERROR_NAME:
        client_packet->type = RGCP_CREATE_GROUP_ERROR_NAME;
        break;
    case WORKERAPI_GROUP_CREATE_ERROR_EXISTS:
        client_packet->type = RGCP_CREATE_GROUP_ERROR_ALREADY_EXISTS;
        break;
    case WORKERAPI_GROUP_JOIN_ERROR_MAX_CLIENTS:
        client_packet->type = RGCP_JOIN_ERROR_MAX_CLIENTS;
        break;
    case WORKERAPI_GROUP_JOIN_ERROR_NO_SUCH_GROUP:
        client_packet->type = RGCP_JOIN_ERROR_NO_SUCH_GROUP;
        break;
    case WORKERAPI_GROUP_JOIN_ERROR_NAME:
        client_packet->type = RGCP_JOIN_ERROR_NAME;
        break;
    case WORKERAPI_GROUP_JOIN_ERROR_ALREADY_IN_GROUP:
        client_packet->type = RGCP_JOIN_ERROR_ALREADY_IN_GROUP;
        break;
    case WORKERAPI_GROUP_JOIN_RESPONSE:
        client_packet->type = RGCP_JOIN_RESPONSE;
        break;
    default:
        client_packet->type = -1;
        break;
    }

    if (client_send(state->clientfd, client_packet) <= 0)
        success = 0;

    free(client_packet);

    return success ? 0 : -1;
}

int handle_client_request(struct worker_state *state)
{
    assert(state);

    struct rgcp_packet *packet = NULL;

    int r = client_recv(state->clientfd, &packet);

    if (r < 0)
    {
        free(packet);
        return -1;
    }

    if (r == 0)
    {
        free(packet);
        state->eof = 1;
        return 0;
    }

    // printf("\t[RGCP worker (%d) client packet] type: 0x%x\n", state->serverfd, packet->type);

    if (execute_client_request(state, packet) < 0)
    {
        free(packet);
        return -1;    
    }

    free(packet);
    return 0;
}

int handle_server_request(struct worker_state *state)
{
    assert(state);

    struct rgcp_workerapi_packet *packet = NULL;

    int r = workerapi_recv(state->serverfd, &packet);

    if (r < 0)
        goto error;

    if (r == 0)
    {
        state->eof = 1;
        goto success;
    }
    
    // printf("\t[RGCP worker (%d) server packet] type: 0x%x\n", state->serverfd, packet->type);

    if (execute_server_request(state, packet) < 0)
        goto error;

success:
    free(packet);
    return 0;
error:
    free(packet);
    return 0;
}

static int handle_incoming(struct worker_state *state)
{
    assert(state);

    int maxfd, success = 1;
    fd_set read_fds;

    FD_ZERO(&read_fds);

    FD_SET(state->serverfd, &read_fds);
    FD_SET(state->clientfd, &read_fds);

    maxfd = max(state->serverfd, state->clientfd);

    if (select(maxfd + 1, &read_fds, NULL, NULL, NULL) < 0)
    {
        perror("Worker select failed");
        return -1;
    }

    if (FD_ISSET(state->clientfd, &read_fds))
    {
        if (handle_client_request(state) != 0)
        {
            success = 0;
        }
    }

    if (FD_ISSET(state->serverfd, &read_fds))
    {
        if (handle_server_request(state) != 0)
        {
            success = 0;
        }
    }

    return success ? 0 : -1;
}

void worker_start(int serverfd, int clientfd)
{
    printf("\t[RGCP worker (%d)] started worker\n", serverfd);

    int success = 1;
    struct worker_state state;

    worker_state_init(&state, clientfd, serverfd);

    while(!state.eof)
    {
        if (handle_incoming(&state) != 0)
        {
            success = 0;
            break;
        }
    }

    worker_state_free(&state);

    exit(success ? 0 : 1);
}
