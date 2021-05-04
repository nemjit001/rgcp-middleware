#include <stdio.h>
#include "system_headers.h"
#include "rgcp_utils.h"
#include "rgcp_worker.h"

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

int worker_handle_incoming(struct worker_state *state)
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
        printf("\t[RGCP worker (%d)] client has data for worker\n", state->serverfd);
    }

    if (FD_ISSET(state->serverfd, &read_fds))
    {
        // handle server incoming data
        printf("\t[RGCP worker (%d)] server has data for worker\n", state->serverfd);
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
        if (worker_handle_incoming(&state) != 0)
        {
            success = 0;
            break;
        }
    }

    worker_state_free(&state);

    exit(success ? 0 : 1);
}
