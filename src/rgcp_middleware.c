#include "system_headers.h"
#include "rgcp_utils.h"
#include "rgcp.h"

#define RGCP_MIDDLEWARE_MAX_CLIENT_BACKLOG 10
#define RGCP_MIDDLEWARE_MAX_CLIENTS 20
#define RGCP_MIDDLEWARE_MAX_GROUPS 5

struct rgcp_middleware_client_info
{
    int sockfd;
    struct sockaddr_in *addrinfo;
};

struct rgcp_middleware_state
{
    int listenfd;
    int client_count;
    struct rgcp_middleware_client_info client_fds[RGCP_MIDDLEWARE_MAX_CLIENTS];
    int group_count;
    struct rgcp_group_info groups[RGCP_MIDDLEWARE_MAX_GROUPS];
};

void close_server_handles(struct rgcp_middleware_state *state)
{
    assert(state);

    for (int i = 0; i < RGCP_MIDDLEWARE_MAX_CLIENTS; i++)
    {
        if (state->client_fds[i].sockfd == -1)
            continue;
        
        close(state->client_fds[i].sockfd);
        free(state->client_fds[i].addrinfo);
    }
}

void rgcp_middleware_state_init(struct rgcp_middleware_state *state)
{
    assert(state);

    memset(state, 0, sizeof(*state));
    state->listenfd = -1;
    state->client_count = 0;
    state->group_count = 0;

    for (int i = 0; i < RGCP_MIDDLEWARE_MAX_CLIENTS; i++)
    {
        state->client_fds[i].sockfd = -1;
        state->client_fds[i].addrinfo = NULL;
    }
}

void rgcp_middleware_state_free(struct rgcp_middleware_state *state)
{
    assert(state);

    close(state->listenfd);
    close_server_handles(state);
}

int create_listen_socket(uint16_t port)
{
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (fd < 0)
    {
        perror("Socket alloc failed");
        return fd;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *) & addr, sizeof(addr)) < 0)
    {
        perror("Bind failed");
        close(fd);
        return -1;
    }

    if (listen(fd, RGCP_MIDDLEWARE_MAX_CLIENT_BACKLOG) < 0)
    {
        perror("Listen failed");
        close(fd);
        return -1;
    }

    return fd;
}

int handle_connection(struct rgcp_middleware_state *state)
{
    assert(state);

    struct sockaddr *addr = calloc(sizeof(struct sockaddr), 1);
    socklen_t addrlen = 0;
    int connfd = accept(state->listenfd, addr, &addrlen);

    if (connfd < 0)
    {
        perror("Accept failed");
        return -1;
    }

    if (state->client_count == RGCP_MIDDLEWARE_MAX_CLIENTS)
    {
        // TODO: send back max clients signal?
        close(connfd);
        return 0;
    }

    for (int i = 0; i < RGCP_MIDDLEWARE_MAX_CLIENTS; i++)
    {
        if (state->client_fds[i].sockfd == -1)
        {
            state->client_fds[i].sockfd = connfd;
            state->client_fds[i].addrinfo = (struct sockaddr_in *) addr;

            state->client_count++;
            printf("new connection\n");
            return 0;
        }
    }

    close(connfd);

    return -1;
}

int handle_request(struct rgcp_middleware_state *state, int fd)
{
    assert(state);

    uint8_t buffer[RGCP_MAX_PACKET_LENGTH];

    memset(buffer, 0, sizeof(buffer));

    if (recv(fd, &buffer, sizeof(buffer), 0) < 0)
    {
        perror("Receive failed");
        return -1;
    }

    struct rgcp_packet *packet = (struct rgcp_packet *) buffer;
    printf("\t [PACKET RECV ( %u )] : %u | %u, %lu\n", fd, packet->id, packet->type, packet->data_length);

    return 0;
}

int handle_incoming(struct rgcp_middleware_state *state)
{
    assert(state);

    int max_fd = -1, success = 1;
    fd_set readfds;
    struct timeval select_timeout = { 0, 0 };

    FD_ZERO(&readfds);
    FD_SET(state->listenfd, &readfds);
    max_fd = state->listenfd;

    for (int i = 0; i < RGCP_MIDDLEWARE_MAX_CLIENTS; i++)
    {
        int fd = state->client_fds[i].sockfd;

        if (fd == -1)
            continue;
                
        FD_SET(fd, &readfds);
        max_fd = max(fd, max_fd);
    }

    if (select(max_fd + 1, &readfds, NULL, NULL, &select_timeout) < 0)
    {
        perror("Select failed");
        return -1;
    }

    if (FD_ISSET(state->listenfd, &readfds))
    {
        if (handle_connection(state) < 0)
        {
            success = 0;
            goto error;
        }
    }

    for (int i = 0; i < RGCP_MIDDLEWARE_MAX_CLIENTS; i++)
    {
        int fd = state->client_fds[i].sockfd;

        if (fd == -1)
            continue;

        if (FD_ISSET(fd, &readfds))
        {
            if (handle_request(state, fd) < 0)
            {
                success = 0;
                goto error;
            }
        }
    }

error:
    return success ? 0 : -1;
}

void connected_clients_check(struct rgcp_middleware_state *state)
{
    assert(state);

    for (int i = 0; i < RGCP_MIDDLEWARE_MAX_CLIENTS; i++)
    {
        // if keep alive is not acknowledged, and client did not signal disconnect, connection should be dropped.

        int fd = state->client_fds[i].sockfd;

        if (fd == -1)
            continue;
        
        //
    }
}

int main()
{
    struct rgcp_middleware_state state;

    rgcp_middleware_state_init(&state);

    state.listenfd = create_listen_socket(RGCP_MIDDLEWARE_PORT);

    if (state.listenfd < 0)
        goto error;

    for(;;)
    {
        connected_clients_check(&state);
        if (handle_incoming(&state) != 0)
            break;
    }

error:
    rgcp_middleware_state_free(&state);

    return 0;
}