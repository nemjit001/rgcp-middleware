#include "system_headers.h"
#include "rgcp_utils.h"
#include "rgcp_worker.h"
#include "rgcp_workerapi.h"
#include "rgcp.h"

#define RGCP_MIDDLEWARE_MAX_CLIENT_BACKLOG 5

// FIXME: put this in config file
#define RGCP_USE_IPV6 0
#define RGCP_MIDDLEWARE_MAX_CLIENTS 100
#define RGCP_MIDDLEWARE_MAX_GROUPS 5
#define RGCP_MIDDLEWARE_MAX_GROUP_MEMBERS ( RGCP_MIDDLEWARE_MAX_CLIENTS / RGCP_MIDDLEWARE_MAX_GROUPS )

struct child
{
    int workerfd;

    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len;
};

struct group
{
    int child_count;
    struct child *children[RGCP_MIDDLEWARE_MAX_GROUP_MEMBERS];
};

struct rgcp_middleware_state
{
    int listenfd;
    int child_count;
    struct child children[RGCP_MIDDLEWARE_MAX_CLIENTS];

    // TODO: actually use this
    struct group groups[RGCP_MIDDLEWARE_MAX_GROUPS];
};

static void handle_sigchld(__attribute__((unused)) int signum)
{
    /* do nothing */
}

static void register_signals(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));

    /* SIGCHLD should interrupt accept */
    sa.sa_handler = handle_sigchld;
    sigaction(SIGCHLD, &sa, NULL);

    /* SIGPIPE should be ignored */
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

void close_serverhandles(struct rgcp_middleware_state *state)
{
    assert(state);

    for (int i = 0; i < RGCP_MIDDLEWARE_MAX_CLIENTS; i++)
    {
        struct child *curr_child = &state->children[i];

        if (curr_child->workerfd == -1)
            continue;
        
        close(curr_child->workerfd);
    }
}

void rgcp_middleware_state_init(struct rgcp_middleware_state *state)
{
    assert(state);

    memset(state, 0, sizeof(*state));
    
    state->child_count = 0;
    state->listenfd = -1;

    for (int i = 0; i < RGCP_MIDDLEWARE_MAX_CLIENTS; i++)
    {
        state->children[i].workerfd = -1;
    }
}

void rgcp_middleware_state_free(struct rgcp_middleware_state *state)
{
    assert(state);

    close_serverhandles(state);
    close(state->listenfd);
}

int create_listen_socket(uint16_t port)
{
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (fd < 0)
    {
        perror("Socket allocation failed");
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

void register_child(struct rgcp_middleware_state *state, int workerfd, struct sockaddr_in peer_addr, socklen_t peer_addr_len)
{
    assert(workerfd >= 0);
    assert(state);

    for (int i = 0; i < RGCP_MIDDLEWARE_MAX_CLIENTS; i++)
    {
        int fd = state->children[i].workerfd;

        if (fd < 0)
        {
            state->child_count++;
            state->children[i].workerfd = workerfd;
            state->children[i].peer_addr = peer_addr;
            state->children[i].peer_addr_len = peer_addr_len;
            return;
        }
    }

    fprintf(stderr, "[RGCP middleware error] Critical error: inconsistent child_count and children, aborting program\n");
    abort();
}

int handle_connection(struct rgcp_middleware_state *state)
{
    assert(state);

    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len = 0;
    pid_t pid = 0;
    int sockets[2];
    int connfd = accept(state->listenfd, (struct sockaddr *) & peer_addr, &peer_addr_len);

    if (connfd < 0)
    {
        if (errno == EINTR)
            return 0;
        perror("Accepting new connection failed");
        return -1;
    }

    if (state->child_count >= RGCP_MIDDLEWARE_MAX_CLIENTS)
    {
        fprintf(stderr, "[RGCP middleware warning] max children exceeded, dropping incoming connection\n");
        return 0;
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0)
    {
        perror("Failed to create comms channel");
        return -1;
    }

    pid = fork();

    if (pid < 0)
    {
        perror("Fork failed");
        close(sockets[0]);
        close(sockets[1]);
        return -1;
    }
    else if (pid == 0)
    {
        // in worker, do worker stuff
        close(sockets[0]);
        close_serverhandles(state);
        
        worker_start(sockets[1], connfd);

        // exit with error if for some reason worker entry function ends up here (shouldn't happen though)
        exit(1);
    }

    // in original application, register child and soldier on
    register_child(state, sockets[0], peer_addr, peer_addr_len);

    close(connfd);
    close(sockets[1]);

    return 0;
}

int handle_worker_close(struct rgcp_middleware_state *state, int worker_index)
{
    assert(state->children[worker_index].workerfd >= 0);
    printf("Closing");

    close(state->children[worker_index].workerfd);
    state->children[worker_index].workerfd = -1;

    memset(&state->children[worker_index].peer_addr, 0, sizeof(struct sockaddr_in));
    state->children[worker_index].peer_addr_len = 0;

    state->child_count--;

    return 0;
}

int handle_worker_request(struct rgcp_middleware_state *state, int worker_index)
{
    struct child *worker = &state->children[worker_index];
    struct rgcp_workerapi_packet packet;
    memset(&packet, 0, sizeof(packet));

    // TODO: use worker api here to read a whole packet and handle accordingly
    int res = workerapi_recv(worker->workerfd, &packet);

    // if worker has died or read has failed, either case return and let handle_children report error
    if (res < 0)
    {
        perror("Read failed");
        return -1;
    }

    if (res == 0)
    {
        return handle_worker_close(state, worker_index);
    }
    
    printf("[RGCP middleware worker packet from (%d)] type: 0x%x\n", worker->workerfd, packet.type);

    switch(packet.type)
    {
    case WORKERAPI_GROUP_CREATE:
        // TODO: create new group
        break;
    case WORKERAPI_GROUP_DISCOVER:
        // TODO: send back group data
        break;
    case WORKERAPI_GROUP_JOIN:
        // TODO: join user to group
        break;
    case WORKERAPI_GROUP_LEAVE:
        // TODO: delete user from group
        break;
    default:
        break;
    }

    return 0;
}

int handle_incoming(struct rgcp_middleware_state *state)
{
    assert(state);

    int success = 1;
    int max_fd = state->listenfd;
    fd_set read_fds;

    FD_ZERO(&read_fds);

    FD_SET(state->listenfd, &read_fds);

    for (int i = 0; i < RGCP_MIDDLEWARE_MAX_CLIENTS; i++)
    {
        int fd = state->children[i].workerfd;

        if (fd < 0)
            continue;

        FD_SET(fd, &read_fds);

        max_fd = max(max_fd, fd);
    }

    if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0)
    {
        // EINTR happens when a worker exits and is reset in the children array
        if (errno == EINTR)
            return 0;

        perror("Select failed");
        return -1;
    }

    if (FD_ISSET(state->listenfd, &read_fds))
    {
        if (handle_connection(state) < 0)
            success = 0;
    }
    
    for (int i = 0; i < RGCP_MIDDLEWARE_MAX_CLIENTS; i++)
    {
        int fd = state->children[i].workerfd;

        if (fd < 0)
            continue;

        if (FD_ISSET(fd, &read_fds))
        {
            if (handle_worker_request(state, i) < 0)
                success = 0;
        }
    }

    return success ? 0 : -1;
}

void check_children(struct rgcp_middleware_state *state)
{
    assert(state);

    for (;;)
    {
        int status;
        pid_t pid = waitpid(0, &status, WNOHANG);

        if (pid < 0 && errno != EINTR && errno != ECHILD)
        {
            perror("waitpid failed");
            abort();
        }
        if (pid == -1 || pid == 0)
        {
            // no children have exited
            break;
        }

        if (WIFSIGNALED(status))
        {
            // exited by signal
            fprintf(stderr, "[RGCP middleware warning] child killed by signal %d\n", WTERMSIG(status));
        }
        else if (!WIFEXITED(status))
        {
            // no signal, dunno what exit cause is
            fprintf(stderr, "[RGCP middleware warning] child died of unknown causes ( exit status = 0x%x )\n", status);
        }
        else if (WEXITSTATUS(status))
        {
            // exited with error
            fprintf(stderr, "[RGCP middleware warning] child exited with error %d\n", WEXITSTATUS(status));
        }
        else
        {
            // exited through natural causes
            printf("[RGCP middleware] child exited\n");
        }
    }
}

int main()
{
    struct rgcp_middleware_state state;

    printf("[RGCP middleware] startup\n");

    rgcp_middleware_state_init(&state);

    register_signals();

    state.listenfd = create_listen_socket(RGCP_MIDDLEWARE_PORT);

    if (state.listenfd < 0)
        goto error;

    printf("[RGCP middleware] ready for connections\n");

    for(;;)
    {
        check_children(&state);
        if (handle_incoming(&state) != 0)
            break;
    }

    printf("[RGCP middleware] shutting down\n");

error:
    rgcp_middleware_state_free(&state);

    return 0;
}