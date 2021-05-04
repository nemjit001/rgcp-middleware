#include <stdio.h>
#include "system_headers.h"
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

    // TODO: recv from client here and handle accordingly

    return 0;
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
