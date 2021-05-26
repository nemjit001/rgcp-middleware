#include "system_headers.h"
#include "rgcp_utils.h"
#include "rgcp_worker.h"
#include "rgcp_workerapi.h"
#include "rgcp.h"

// FIXME: put this in config file
#define RGCP_MIDDLEWARE_PORT 8000
#define RGCP_MIDDLEWARE_USE_IPV6 0
#define RGCP_MIDDLEWARE_MAX_CLIENT_BACKLOG 5
#define RGCP_MIDDLEWARE_MAX_CLIENTS 100
#define RGCP_MIDDLEWARE_MAX_GROUPS 5
#define RGCP_MIDDLEWARE_MAX_GROUP_MEMBERS ( RGCP_MIDDLEWARE_MAX_CLIENTS / RGCP_MIDDLEWARE_MAX_GROUPS )
#define RGCP_MIDDLEWARE_GROUPNAME_LENGTH 20

struct child
{
    int workerfd;

    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len;
};

struct group
{
    char group_name[RGCP_MIDDLEWARE_GROUPNAME_LENGTH];
    int active;
    uint32_t child_count;
    struct child *children[RGCP_MIDDLEWARE_MAX_GROUP_MEMBERS];
};

struct rgcp_middleware_state
{
    int listenfd;
    uint32_t child_count;
    struct child children[RGCP_MIDDLEWARE_MAX_CLIENTS];

    uint32_t group_count;
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

void convert_middleware_to_lib_repr(struct group *mw_group, struct rgcp_group_info *rgcp_group)
{
    assert(mw_group);
    assert(rgcp_group);

    rgcp_group->name_length = strlen(mw_group->group_name) + 1;  // +1 accounts for null byte
    rgcp_group->peer_count = mw_group->child_count;

    rgcp_group->group_name = calloc(rgcp_group->name_length, sizeof(char));
    memcpy(rgcp_group->group_name, mw_group->group_name, rgcp_group->name_length);
    rgcp_group->peers = calloc(rgcp_group->peer_count, sizeof(struct rgcp_peer_info));

    int child_index = 0;
    for (int j = 0; j < RGCP_MIDDLEWARE_MAX_GROUP_MEMBERS; j++)
    {
        if (mw_group->children[j] == NULL)
            continue;
        
        struct rgcp_peer_info *peer_info = &rgcp_group->peers[child_index];
        peer_info->addr = mw_group->children[j]->peer_addr;
        peer_info->addrlen = mw_group->children[j]->peer_addr_len;
        
        child_index++;
    }
}

int unpack_group_info_packet(struct rgcp_group_info *info, struct rgcp_workerapi_packet *packet, uint32_t offset_start)
{
    assert(packet);

    uint32_t data_length = packet->packet_len - sizeof(struct rgcp_workerapi_packet);

    if (data_length == 0)
        return -1;

    uint32_t offset = offset_start;

    if (data_length < offset + sizeof(uint32_t))
        return -1;

    memcpy(&info->name_length, packet->data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    if (data_length < offset + (info->name_length * sizeof(char)))
        return -1;

    info->group_name = calloc(info->name_length, sizeof(char));
    memcpy(info->group_name, packet->data + offset, info->name_length * sizeof(char));

    offset += info->name_length * sizeof(char);

    if (data_length < offset + sizeof(uint32_t))
        return -1;

    memcpy(&info->peer_count, packet->data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    if (data_length < offset + (info->peer_count * sizeof(struct rgcp_peer_info)))
        return -1;

    info->peers = calloc(info->peer_count, sizeof(struct rgcp_peer_info));
    memcpy(info->peers, packet->data + offset, info->peer_count * sizeof(struct rgcp_peer_info));
    offset += info->peer_count * sizeof(struct rgcp_peer_info);

    return offset;
}

int pack_group_info_packet(struct rgcp_group_info *info, uint8_t *array)
{
    assert(info);
    assert(array);

    uint32_t offset = 0;

    memcpy(array, &info->name_length, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    memcpy(array + offset, info->group_name, info->name_length * sizeof(char));
    offset += info->name_length * sizeof(char);

    memcpy(array + offset, &info->peer_count, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    memcpy(array + offset, info->peers, info->peer_count * sizeof(struct rgcp_peer_info));
    offset += info->peer_count * sizeof(struct rgcp_peer_info);

    return offset;
}

int pack_peer_info_packet(struct rgcp_peer_info *info, uint8_t *array)
{
    assert(info);
    assert(array);

    memcpy(array, info, sizeof(struct rgcp_peer_info));

    return sizeof(struct rgcp_peer_info);
}

int group_exists(struct rgcp_middleware_state *state, const char *groupname)
{
    assert(state);
    assert(groupname);

    for (int i = 0; i < RGCP_MIDDLEWARE_MAX_GROUPS; i++)
    {
        if (state->groups[i].active != 1)
            continue;
        
        if (strcmp(state->groups[i].group_name, groupname) == 0)
            return 1;
    }

    return 0;
}

int broadcast_client_join(struct child *worker, struct group *mw_group)
{
    assert(worker);
    assert(mw_group);

    for (uint32_t i = 0; i < RGCP_MIDDLEWARE_MAX_GROUP_MEMBERS; i++)
    {
        if (mw_group->children[i] == NULL)
            continue;
        
        struct rgcp_peer_info peer_info;
        memset(&peer_info, 0, sizeof(peer_info));

        peer_info.addr = worker->peer_addr;
        peer_info.addrlen = worker->peer_addr_len;

        uint32_t packet_len = sizeof(struct rgcp_workerapi_packet) + sizeof(struct rgcp_peer_info);
        struct rgcp_workerapi_packet *packet = calloc(packet_len, 1);
        memset(packet, 0, packet_len);

        packet->packet_len = packet_len;
        packet->type = WORKERAPI_NEW_GROUP_MEMBER;

        if (pack_peer_info_packet(&peer_info, packet->data) < 0)
        {
            free(packet);
            return -1;
        }

        if (workerapi_send(mw_group->children[i]->workerfd, packet) < 0)
        {
            free(packet);
            return -1;
        }

        free(packet);
    }

    return 0;
}

int broadcast_client_leave(struct child *worker, struct group *mw_group)
{
    assert(worker);
    assert(mw_group);

    for (uint32_t i = 0; i < RGCP_MIDDLEWARE_MAX_GROUP_MEMBERS; i++)
    {
        if (mw_group->children[i] == NULL)
            continue;
        
        struct rgcp_peer_info peer_info;
        memset(&peer_info, 0, sizeof(peer_info));

        peer_info.addr = worker->peer_addr;
        peer_info.addrlen = worker->peer_addr_len;

        uint32_t packet_len = sizeof(struct rgcp_workerapi_packet) + sizeof(struct rgcp_peer_info);
        struct rgcp_workerapi_packet *packet = calloc(packet_len, 1);
        memset(packet, 0, packet_len);

        packet->packet_len = packet_len;
        packet->type = WORKERAPI_DELETE_GROUP_MEMBER;

        if (pack_peer_info_packet(&peer_info, packet->data) < 0)
        {
            free(packet);
            return -1;
        }

        if (workerapi_send(mw_group->children[i]->workerfd, packet) < 0)
        {
            free(packet);
            return -1;
        }

        free(packet);
    }

    return 0;
}

int is_worker_in_group(struct child *worker, struct group *mw_group)
{
    assert(worker);
    assert(mw_group);

    for (int i = 0; i < RGCP_MIDDLEWARE_MAX_GROUP_MEMBERS; i++)
    {
        if (mw_group->children[i] == NULL)
            continue;

        if (mw_group->children[i] == worker) return 1;
    }

    return 0;
}

int remove_worker_from_group(struct rgcp_middleware_state *state, struct child *worker, struct group *mw_group)
{
    assert(state);
    assert(worker);
    assert(mw_group);

    if (is_worker_in_group(worker, mw_group) == 0)
        return -1;

    int is_deleted = 0;

    for (uint32_t i = 0; i < RGCP_MIDDLEWARE_MAX_GROUP_MEMBERS; i++)
    {
        if (mw_group->children[i] == NULL)
            continue;
        
        if (mw_group->children[i] == worker)
        {
            printf("[RGCP middleware] Worker (%d) is leaving group (%s)\n", worker->workerfd, mw_group->group_name);

            mw_group->children[i] = NULL;
            mw_group->child_count--;

            is_deleted = 1;

            break;
        }
    }

    if (is_deleted == 0)
        return -1;

    if (broadcast_client_leave(worker, mw_group) < 0)
        return -1;

    // delete group if no more clients
    if (mw_group->child_count == 0)
    {
        printf("[RGCP middleware] Deleted group (%s) due to no active clients\n", mw_group->group_name);
        mw_group->active = 0;
        memset(mw_group->group_name, 0, sizeof(mw_group->group_name));
        memset(mw_group->children, 0, sizeof(mw_group->children));

        state->group_count--;
    }

    return 0;
}

struct group *get_group_by_name(struct rgcp_middleware_state *state, const char *groupname)
{
    for (int i = 0; i < RGCP_MIDDLEWARE_MAX_GROUPS; i++)
    {
        if (state->groups[i].active != 1)
            continue;
        
        if (strcmp(state->groups[i].group_name, groupname) == 0)
            return &state->groups[i];
    }

    return NULL;
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
        state->children[i].peer_addr_len = 0;

        memset(&state->children[i].peer_addr, 0, sizeof(state->children[i].peer_addr));
    }

    for (int i = 0; i < RGCP_MIDDLEWARE_MAX_GROUPS; i++)
    {
        state->groups[i].active = 0;
        state->groups[i].child_count = 0;

        memset(state->groups[i].group_name, 0, sizeof(state->groups[i].group_name));
        memset(state->groups[i].children, 0, sizeof(state->groups[i].children));
    }
}

void rgcp_middleware_state_free(struct rgcp_middleware_state *state)
{
    assert(state);

    close_serverhandles(state);

    if (state->listenfd >= 0)
        close(state->listenfd);
}

int create_listen_socket(uint16_t port)
{
    struct sockaddr_in addr;

    int domain = AF_INET;

    if (RGCP_MIDDLEWARE_USE_IPV6)
        domain = AF_INET6;

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (fd < 0)
    {
        perror("Socket allocation failed");
        return fd;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = domain;
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
    socklen_t peer_addr_len = sizeof(peer_addr);
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

    // TODO: notify groups that worker has closed and client has left
    for (uint32_t i = 0; i < RGCP_MIDDLEWARE_MAX_GROUPS; i++)
    {
        if (state->groups[i].active == 0)
            continue;

        if (is_worker_in_group(&state->children[worker_index], &state->groups[i]) == 0)
            continue;
        
        if (remove_worker_from_group(state, &state->children[worker_index], &state->groups[i]) < 0)
            return -1;
    }

    close(state->children[worker_index].workerfd);
    state->children[worker_index].workerfd = -1;

    memset(&state->children[worker_index].peer_addr, 0, sizeof(state->children[worker_index].peer_addr));
    state->children[worker_index].peer_addr_len = 0;

    state->child_count--;

    return 0;
}

int send_create_group_response(struct child *worker, enum workerapi_req_type type)
{
    if (type != WORKERAPI_GROUP_CREATE_OK && type != WORKERAPI_GROUP_CREATE_ERROR_NAME && type != WORKERAPI_GROUP_CREATE_ERROR_GROUPS)
        return -1;
    
    struct rgcp_workerapi_packet packet;
    memset(&packet, 0, sizeof(packet));
    
    packet.type = type;
    packet.packet_len = sizeof(packet);

    int res = workerapi_send(worker->workerfd, &packet);

    return res;
}

int create_new_group(struct child *worker, struct rgcp_middleware_state *state, struct rgcp_workerapi_packet *packet)
{
    union rgcp_packet_data data;
    memset(&data, 0, sizeof(data));

    if (unpack_group_info_packet(&data.group_info, packet, 0) < 0)
    {
        rgcp_group_info_free(&data.group_info);
        return -1;
    }

    if (state->group_count >= RGCP_MIDDLEWARE_MAX_GROUPS)
    {
        rgcp_group_info_free(&data.group_info);
        fprintf(stderr, "[RGCP middleware warning] max groups exceeded, dropping creation request\n");
        return send_create_group_response(worker, WORKERAPI_GROUP_CREATE_ERROR_GROUPS);
    }

    if (data.group_info.name_length > RGCP_MIDDLEWARE_GROUPNAME_LENGTH || data.group_info.name_length == 0)
    {
        rgcp_group_info_free(&data.group_info);
        fprintf(stderr, "[RGCP middleware warning] group name length is too long or zero, dropping creation request\n");
        return send_create_group_response(worker, WORKERAPI_GROUP_CREATE_ERROR_NAME);
    }

    if (group_exists(state, data.group_info.group_name) == 1)
    {
        rgcp_group_info_free(&data.group_info);
        fprintf(stderr, "[RGCP middleware warning] group already exists, dropping creation request\n");
        return send_create_group_response(worker, WORKERAPI_GROUP_CREATE_ERROR_EXISTS);
    }

    for (int i = 0; i < RGCP_MIDDLEWARE_MAX_GROUPS; i++)
    {
        if (state->groups[i].active == 0)
        {
            state->group_count++;

            // inactive group found     
            struct group *curr_group = &state->groups[i];

            memcpy(&curr_group->group_name, data.group_info.group_name, data.group_info.name_length);
            curr_group->active = 1;
            curr_group->child_count = 0;

            // zero children just to be sure
            memset(curr_group->children, 0, sizeof(curr_group->children));

            printf("[RGCP middleware] Added group (%s)\n", curr_group->group_name);

            rgcp_group_info_free(&data.group_info);

            return send_create_group_response(worker, WORKERAPI_GROUP_CREATE_OK);
        }
    }

    rgcp_group_info_free(&data.group_info);
    fprintf(stderr, "[RGCP middleware error] Critical error: inconsistent group_count and groups, aborting program\n");
    return -1;
}

int handle_group_discovery(struct rgcp_middleware_state *state, struct child *worker)
{
    assert(state);
    assert(worker);

    int group_index = 0;
    struct group mw_groups[state->group_count];
    struct rgcp_group_info rgcp_groups[state->group_count];

    // get all active groups
    for (int i = 0; i < RGCP_MIDDLEWARE_MAX_GROUPS; i++)
    {
        if (state->groups[i].active != 1)
            continue;
        
        mw_groups[group_index] = state->groups[i];
        group_index++;
    }

    // convert our representation to rgcp lib representation
    for (uint32_t i = 0; i < state->group_count; i++)
    {
        struct group *curr_mw_group = &mw_groups[i];
        struct rgcp_group_info *curr_rgcp_group = &rgcp_groups[i];

        convert_middleware_to_lib_repr(curr_mw_group, curr_rgcp_group);
    }

    struct rgcp_workerapi_packet *packet = calloc(sizeof(struct rgcp_workerapi_packet), 1);
    uint32_t packet_len = sizeof(packet) + sizeof(state->group_count) + state->group_count * sizeof(struct rgcp_group_info);
    
    packet = realloc(packet, packet_len);
    memset(packet, 0, packet_len);
    packet->type = WORKERAPI_GROUP_DISCOVER_RESPONSE;
    packet->packet_len = packet_len;
    
    uint32_t offset = 0;
    memcpy(packet->data, &state->group_count, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    for (uint32_t i = 0; i < state->group_count; i++)
    {
        int res = pack_group_info_packet(&rgcp_groups[i], packet->data + offset);

        if (res < 0)
            return -1;
        
        offset += res;
    }

    if (workerapi_send(worker->workerfd, packet) < 0)
    {
        for (uint32_t i = 0; i < state->group_count; i++)
        {
            free(rgcp_groups[i].group_name);
            free(rgcp_groups[i].peers);
        }

        free(packet);
        return -1;
    }

    for (uint32_t i = 0; i < state->group_count; i++)
    {
        free(rgcp_groups[i].group_name);
        free(rgcp_groups[i].peers);
    }

    free(packet);

    return 0;
}

int send_join_group_response(struct child *worker, enum workerapi_req_type type)
{
    if (
        type != WORKERAPI_GROUP_JOIN_ERROR_NAME && 
        type != WORKERAPI_GROUP_JOIN_ERROR_NO_SUCH_GROUP && 
        type != WORKERAPI_GROUP_JOIN_ERROR_MAX_CLIENTS &&
        type != WORKERAPI_GROUP_JOIN_ERROR_ALREADY_IN_GROUP
    )
    {
        return -1;
    }
    
    struct rgcp_workerapi_packet packet;
    memset(&packet, 0, sizeof(packet));
    
    packet.type = type;
    packet.packet_len = sizeof(packet);

    int res = workerapi_send(worker->workerfd, &packet);

    return res;
}

int notify_client_join_ok(struct child *worker, struct group *mw_group)
{
    struct rgcp_workerapi_packet *out_packet = calloc(sizeof(struct rgcp_workerapi_packet), 1);
    uint32_t packet_len = sizeof(*out_packet) + sizeof(struct rgcp_group_info);

    out_packet = realloc(out_packet, packet_len);
    memset(out_packet, 0, packet_len);

    out_packet->type = WORKERAPI_GROUP_JOIN_RESPONSE;
    out_packet->packet_len = packet_len;

    struct rgcp_group_info out_group_info;

    rgcp_group_info_init(&out_group_info);
    convert_middleware_to_lib_repr(mw_group, &out_group_info);

    if (pack_group_info_packet(&out_group_info, out_packet->data) < 0)
    {
        rgcp_group_info_free(&out_group_info);
        free(out_packet);
        return -1;
    }

    if (workerapi_send(worker->workerfd, out_packet) < 0)
    {
        rgcp_group_info_free(&out_group_info);
        free(out_packet);
        return -1;
    }
    
    rgcp_group_info_free(&out_group_info);
    free(out_packet);

    return 0;
}

int handle_group_join(struct rgcp_middleware_state *state, struct child *worker, struct rgcp_workerapi_packet *packet)
{
    assert(state);
    assert(worker);
    assert(packet);

    // add to group list  + notify all other group members that new member has joined

    union rgcp_packet_data data;
    memset(&data, 0, sizeof(data));

    if (unpack_group_info_packet(&data.group_info, packet, 0) < 0)
    {
        rgcp_group_info_free(&data.group_info);
        return -1;
    }

    if (data.group_info.name_length > RGCP_MIDDLEWARE_GROUPNAME_LENGTH || data.group_info.name_length == 0)
    {
        rgcp_group_info_free(&data.group_info);
        fprintf(stderr, "[RGCP middleware warning] group name length is too long or zero, dropping join request\n");
        return send_join_group_response(worker, WORKERAPI_GROUP_JOIN_ERROR_NAME);
    }

    if (group_exists(state, data.group_info.group_name) == 0)
    {
        rgcp_group_info_free(&data.group_info);
        fprintf(stderr, "[RGCP middleware warning] group does not exist, dropping join request\n");
        return send_join_group_response(worker, WORKERAPI_GROUP_JOIN_ERROR_NO_SUCH_GROUP);
    }

    printf("[RGCP middleware] Worker (%d) is joining group (%s)\n", worker->workerfd, data.group_info.group_name);
    struct group *curr_group = get_group_by_name(state, data.group_info.group_name);

    if (curr_group == NULL)
    {
        rgcp_group_info_free(&data.group_info);
        fprintf(stderr, "[RGCP middleware warning] inconsistent group existence, exiting program\n");
        return -1;
    }

    if (curr_group->child_count > RGCP_MIDDLEWARE_MAX_GROUP_MEMBERS)
    {
        rgcp_group_info_free(&data.group_info);
        fprintf(stderr, "[RGCP middleware warning] max group members exceeded, dropping join request\n");
        return send_join_group_response(worker, WORKERAPI_GROUP_JOIN_ERROR_MAX_CLIENTS);
    }

    if (is_worker_in_group(worker, curr_group) == 1)
    {
        rgcp_group_info_free(&data.group_info);
        fprintf(stderr, "[RGCP middleware warning] client already in group, dropping join request\n");
        return send_join_group_response(worker, WORKERAPI_GROUP_JOIN_ERROR_ALREADY_IN_GROUP);
    }

    if (notify_client_join_ok(worker, curr_group) < 0)
    {
        rgcp_group_info_free(&data.group_info);
        return -1;
    }

    if (broadcast_client_join(worker, curr_group) < 0)
    {
        rgcp_group_info_free(&data.group_info);
        return -1;
    }

    int success = 0;

    for (int i = 0; i < RGCP_MIDDLEWARE_MAX_GROUP_MEMBERS; i++)
    {
        if (curr_group->children[i] == NULL)
        {
            // empty spot found        
            curr_group->children[i] = worker;
            curr_group->child_count++;
            success = 1;
            break;
        }
    }

    if (success != 1)
    {
        rgcp_group_info_free(&data.group_info);
        fprintf(stderr, "[RGCP middleware error] Critical error: inconsistent member count and actual members, aborting program\n");
        abort();
    }

    rgcp_group_info_free(&data.group_info);

    return 0;
}

int handle_group_leave(struct rgcp_middleware_state *state, struct child *worker, struct rgcp_workerapi_packet *packet)
{
    assert(state);
    assert(worker);
    assert(packet);

    // remove from group list  + notify all other group members that member has left
    // if last to leave, disband group and set group to inactive

    // TODO: implement this

    union rgcp_packet_data data;
    memset(&data, 0, sizeof(data));

    if (unpack_group_info_packet(&data.group_info, packet, 0) < 0)
    {
        rgcp_group_info_free(&data.group_info);
        return -1;
    }

    struct group *mw_group = get_group_by_name(state, data.group_info.group_name);
    if (remove_worker_from_group(state, worker, mw_group) < 0)
        return 0;

    return 0;
}

int execute_worker_request(struct rgcp_middleware_state *state, int worker_index, struct rgcp_workerapi_packet *packet)
{
    assert(state);
    assert(packet);

    struct child *worker = &state->children[worker_index];

    switch(packet->type)
    {
    case WORKERAPI_GROUP_CREATE:
        return create_new_group(worker, state, packet);
    case WORKERAPI_GROUP_DISCOVER:
        return handle_group_discovery(state, worker);
    case WORKERAPI_GROUP_JOIN:
        return handle_group_join(state, worker, packet);
    case WORKERAPI_GROUP_LEAVE:
        return handle_group_leave(state, worker, packet);
    default:
        printf("[RGCP middleware] received unknown packet of type 0x%x\n", packet->type);
        break;
    }

    return 0;
}

int handle_worker_request(struct rgcp_middleware_state *state, int worker_index)
{
    assert(state);

    struct child *worker = &state->children[worker_index];
    struct rgcp_workerapi_packet *packet = NULL;

    int res = workerapi_recv(worker->workerfd, &packet);

    // Worker has died or read has failed, either case return and let handle_children report error
    if (res < 0)
    {
        perror("Read from worker failed");
        free(packet);
        return -1;
    }

    if (res == 0)
    {
        free(packet);
        return handle_worker_close(state, worker_index);
    }
    
    // FIXME: remove this when handling works
    printf("[RGCP middleware worker packet from (%d)] type: 0x%x\n", worker->workerfd, packet->type);

    if (execute_worker_request(state, worker_index, packet) < 0)
    {
        free(packet);
        return -1;
    }

    free(packet);

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