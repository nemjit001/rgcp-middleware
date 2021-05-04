#include <stdio.h>
#include "system_headers.h"
#include "rgcp_utils.h"
#include "rgcp_worker.h"
#include "rgcp.h"

struct worker_state
{
    int serverfd;
    int clientfd;
    int eof;
};

void worker_state_init(struct worker_state *state)
{
    memset(state, 0, sizeof(*state));
}

void worker_state_free(struct worker_state *state)
{
    assert(state);
    close(state->clientfd);
    close(state->serverfd);
}

int client_recv(int fd, struct rgcp_packet *packet)
{
    // FIXME: change 2048 -> max packet size, only know when packet struct fully defined
    uint8_t buffer[2048];
    ssize_t packet_size_bytes = recv(fd, buffer, sizeof(buffer), 0);

    if (packet_size_bytes <= 0)
        return -1;

    memcpy(packet, buffer, packet_size_bytes);

    return 0;
}

int client_send(__attribute__((unused)) int fd, __attribute__((unused)) struct rgcp_packet *packet)
{
    // TODO: implement send

    return -1;
}

int handle_client_request(struct worker_state *state)
{
    assert(state);

    struct rgcp_packet packet;

    if (client_recv(state->clientfd, &packet) < 0)
        return -1;

    // TODO: handle packet type here

    return 0;
}

int handle_server_request(__attribute__((unused)) struct worker_state *state)
{
    assert(state);

    // TODO: implement handler function

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
        // handle client incoming data
        printf("\t[RGCP worker (%d)] client can be read from\n", state->serverfd);

        if (handle_client_request(state) != 0)
            success = 0;
    }

    if (FD_ISSET(state->serverfd, &read_fds))
    {
        // handle server incoming data
        printf("\t[RGCP worker (%d)] server can be read from\n", state->serverfd);

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

    worker_state_init(&state);

    state.clientfd = clientfd;
    state.serverfd = serverfd;

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
