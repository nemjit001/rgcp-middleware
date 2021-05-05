#include <stdio.h>
#include "system_headers.h"
#include "rgcp_utils.h"
#include "rgcp_worker.h"
#include "rgcp_workerapi.h"
#include "rgcp.h"

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

int client_recv(int fd, struct rgcp_packet *packet)
{
    assert(fd >= 0);
    assert(packet);

    // FIXME: change 2048 -> max packet size, only know when packet struct fully defined
    uint8_t buffer[2048];
    ssize_t packet_size_bytes = recv(fd, buffer, sizeof(buffer), 0);

    // If empty or error remote client has exited or closed socket
    if (packet_size_bytes < 0)
        return -1;

    if (packet_size_bytes == 0)
        return 0;

    memcpy(packet, buffer, packet_size_bytes);

    return packet_size_bytes;
}

int client_send(int fd, struct rgcp_packet *packet)
{
    assert(fd >= 0);
    assert(packet);

    ssize_t packet_size_bytes = send(fd, (uint8_t *)packet, sizeof(*packet), 0);

    // If empty or error remote client has exited or closed socket
    if (packet_size_bytes < 0)
        return -1;

    return packet_size_bytes;
}

int handle_client_request(struct worker_state *state)
{
    assert(state);

    struct rgcp_packet packet;

    int r = client_recv(state->clientfd, &packet);

    if (r < 0)
        return -1;

    if (r == 0)
    {
        state->eof = 1;
        return 0;
    }

    printf("\t[RGCP worker (%d) client packet] type: 0x%x\n", state->serverfd, packet.type);

    // TODO: handle packet here
    switch(packet.type)
    {
    default:
        break;
    }

    return 0;
}

int handle_server_request(struct worker_state *state)
{
    assert(state);

    struct rgcp_workerapi_packet packet;
    memset(&packet, 0, sizeof(packet));

    int r = workerapi_recv(state->serverfd, &packet);
    if (r < 0)
        return -1;

    if (r == 0)
    {
        state->eof = 1;
        return 0;
    }
    
    printf("\t[RGCP worker (%d) server packet] type: 0x%x\n", state->serverfd, packet.type);

    // TODO: handle packet here
    switch(packet.type)
    {
    case WORKERAPI_GROUP_DISCOVER_RESPONSE:
        // TODO: forward group data to client
        break;
    case WORKERAPI_NEW_GROUP_MEMBER:
        // TODO: forward new group member to client
        break;
    case WORKERAPI_DELETE_GROUP_MEMBER:
        // TODO: forward delete of member to client
        break;
    default:
        break;
    }

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
            success = 0;
    }

    if (FD_ISSET(state->serverfd, &read_fds))
    {
        if (handle_server_request(state) != 0)
            success = 0;
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
